defmodule Ret.OIDCSession do
  @moduledoc """
  AVN: A single OIDC sign-in. Keeps the provider's refresh token server-side and hands the client only
  short-lived access tokens, which it renews through `RetWeb.Api.V1.OIDCSessionController`.

  The provider rotates refresh tokens and treats reuse of a spent one as theft (revoking the whole chain),
  so every refresh runs under a row lock and a still-fresh access token is returned instead of refreshing
  again. That makes concurrent callers (several tabs, several reticulum nodes) safe.
  """
  use Ecto.Schema
  import Ecto.Query

  require Logger

  alias Ret.{Account, OIDCSession, RemoteOIDCClient, Repo}

  @schema_prefix "ret0"
  @primary_key {:oidc_session_id, :id, autogenerate: true}

  # Hand out a cached access token only if it has at least this long to live
  @reuse_margin_seconds 300
  # Provider refresh tokens outlive this (Hydra default 720h); older rows can never refresh again
  @stale_after_days 31

  schema "oidc_sessions" do
    field :session_key, :string
    field :refresh_token, Ret.EncryptedField
    field :access_token, Ret.EncryptedField
    field :access_token_expires_at, :utc_datetime

    belongs_to :account, Account, references: :account_id

    timestamps()
  end

  @doc "Records a new sign-in and returns its session key, or nil when the provider issued no refresh token"
  def create_for_account(_account, %{"refresh_token" => refresh_token})
      when refresh_token in [nil, ""],
      do: nil

  def create_for_account(%Account{} = account, %{"refresh_token" => refresh_token, "access_token" => access_token} = tokens) do
    prune_stale()
    session_key = SecureRandom.urlsafe_base64(32)

    %OIDCSession{}
    |> Ecto.Changeset.change(
      session_key: session_key,
      account_id: account.account_id,
      refresh_token: refresh_token,
      access_token: access_token,
      access_token_expires_at: expires_at(tokens)
    )
    |> Repo.insert!()

    session_key
  end

  def create_for_account(_account, _tokens) do
    Logger.warn("OIDC token response has no refresh_token; is offline_access in the OIDC scopes?")
    nil
  end

  @doc """
  Returns `{:ok, access_token}` with at least a few minutes to live, refreshing with the provider if needed.
  `{:error, :not_found}` and `{:error, :rejected}` mean the client must sign in again;
  `{:error, :unavailable}` is transient.
  """
  def fresh_access_token(%Account{} = account, session_key) when is_binary(session_key) do
    result = Repo.transaction(fn ->
      session =
        from(s in OIDCSession,
          where: s.session_key == ^session_key and s.account_id == ^account.account_id,
          lock: "FOR UPDATE"
        )
        |> Repo.one()

      cond do
        is_nil(session) ->
          Repo.rollback(:not_found)

        still_fresh?(session) ->
          session.access_token

        true ->
          refresh(session)
      end
    end)

    # The refresh token is dead, so this sign-in is over. Deleted outside the transaction, which rolled back.
    if result == {:error, :rejected} do
      from(s in OIDCSession, where: s.session_key == ^session_key) |> Repo.delete_all()
    end

    result
  end

  def fresh_access_token(_account, _session_key), do: {:error, :not_found}

  @doc "Ends a sign-in: forgets the session and revokes its refresh token with the provider (best effort)"
  def delete_for_account(%Account{} = account, session_key) when is_binary(session_key) do
    session =
      from(s in OIDCSession, where: s.session_key == ^session_key and s.account_id == ^account.account_id)
      |> Repo.one()

    if session do
      Repo.delete!(session)
      revoke(session.refresh_token)
    end

    :ok
  end

  def delete_for_account(_account, _session_key), do: :ok

  defp refresh(session) do
    case request_tokens(grant_type: "refresh_token", refresh_token: session.refresh_token) do
      {:ok, %{"access_token" => access_token} = tokens} ->
        session
        |> Ecto.Changeset.change(
          access_token: access_token,
          # Rotating providers issue a new refresh token each time; keep the old one if this one doesn't
          refresh_token: Map.get(tokens, "refresh_token") || session.refresh_token,
          access_token_expires_at: expires_at(tokens)
        )
        |> Repo.update!()

        access_token

      {:error, reason} ->
        Repo.rollback(reason)
    end
  end

  defp request_tokens(grant) do
    body =
      {:form,
       [
         client_id: RemoteOIDCClient.get_client_id(),
         client_secret: RemoteOIDCClient.get_client_secret()
       ] ++ grant}

    headers = [{"content-type", "application/x-www-form-urlencoded"}]

    case HTTPoison.post(RemoteOIDCClient.get_token_endpoint(), body, headers, timeout: 10_000, recv_timeout: 10_000) do
      {:ok, %HTTPoison.Response{status_code: status, body: resp_body}} when status in 200..299 ->
        case Poison.decode(resp_body) do
          {:ok, %{"access_token" => _} = tokens} -> {:ok, tokens}
          _ -> {:error, :unavailable}
        end

      # RFC 6749 §5.2: invalid_grant etc. arrive as 400 (or 401 for client auth failures)
      {:ok, %HTTPoison.Response{status_code: status, body: resp_body}} when status in [400, 401] ->
        Logger.warn("OIDC refresh rejected (#{status}): #{resp_body}")
        {:error, :rejected}

      other ->
        Logger.warn("OIDC refresh failed: #{inspect(other)}")
        {:error, :unavailable}
    end
  end

  defp revoke(refresh_token) do
    case RemoteOIDCClient.get_revocation_endpoint() do
      nil ->
        :ok

      url ->
        body =
          {:form,
           [
             client_id: RemoteOIDCClient.get_client_id(),
             client_secret: RemoteOIDCClient.get_client_secret(),
             token: refresh_token,
             token_type_hint: "refresh_token"
           ]}

        headers = [{"content-type", "application/x-www-form-urlencoded"}]

        case HTTPoison.post(url, body, headers, timeout: 10_000, recv_timeout: 10_000) do
          {:ok, %HTTPoison.Response{status_code: status}} when status in 200..299 -> :ok
          other -> Logger.warn("OIDC refresh token revocation failed: #{inspect(other)}")
        end
    end
  end

  defp still_fresh?(%OIDCSession{access_token_expires_at: expires_at}) do
    DateTime.diff(expires_at, DateTime.utc_now()) > @reuse_margin_seconds
  end

  defp expires_at(tokens) do
    # expires_in is REQUIRED-ish (RFC 6749 recommends it); assume a conservative 5 minutes if absent
    seconds =
      case Map.get(tokens, "expires_in") do
        n when is_integer(n) and n > 0 -> n
        _ -> 300
      end

    DateTime.utc_now() |> DateTime.add(seconds, :second) |> DateTime.truncate(:second)
  end

  defp prune_stale() do
    cutoff = NaiveDateTime.utc_now() |> NaiveDateTime.add(-@stale_after_days * 24 * 60 * 60, :second)
    from(s in OIDCSession, where: s.updated_at < ^cutoff) |> Repo.delete_all()
  end
end
