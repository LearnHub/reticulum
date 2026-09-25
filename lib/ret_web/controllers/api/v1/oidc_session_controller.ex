defmodule RetWeb.Api.V1.OIDCSessionController do
  @moduledoc """
  AVN: Renews the OIDC access token that the client passes through to the Eduverse Connect services.
  Authenticated by the reticulum credentials token; the session key names the sign-in (see `Ret.OIDCSession`).
  """
  use RetWeb, :controller

  alias Ret.OIDCSession

  def refresh(conn, %{"session" => session_key}) when is_binary(session_key) do
    account = Guardian.Plug.current_resource(conn)

    case OIDCSession.fresh_access_token(account, session_key) do
      {:ok, access_token} ->
        conn |> json(%{access_token: access_token})

      {:error, :unavailable} ->
        conn |> put_status(503) |> json(%{error: "unavailable"})

      # :not_found or :rejected; the client must sign in again
      {:error, _} ->
        conn |> put_status(401) |> json(%{error: "sign_in_required"})
    end
  end

  def refresh(conn, _params), do: conn |> put_status(400) |> json(%{error: "session required"})

  def sign_out(conn, params) do
    account = Guardian.Plug.current_resource(conn)
    OIDCSession.delete_for_account(account, params["session"])
    conn |> json(%{})
  end
end
