defmodule Ret.Repo.Migrations.CreateOidcSessionsTable do
  use Ecto.Migration

  # AVN: One row per OIDC sign-in, holding the provider refresh token server-side so the client
  # can renew its short-lived access token without ever seeing the refresh token
  def change do
    create table(:oidc_sessions, primary_key: false) do
      add :oidc_session_id, :bigint,
        default: fragment("ret0.next_id()"),
        primary_key: true

      add :session_key, :string, null: false
      add :account_id, references(:accounts, column: :account_id, on_delete: :delete_all), null: false
      add :refresh_token, :binary, null: false
      add :access_token, :binary, null: false
      add :access_token_expires_at, :utc_datetime, null: false
      timestamps()
    end

    create unique_index(:oidc_sessions, [:session_key])
    create index(:oidc_sessions, [:account_id])
    create index(:oidc_sessions, [:updated_at])
  end
end
