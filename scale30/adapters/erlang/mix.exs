defmodule Scale30Erlang.MixProject do
  use Mix.Project

  def project do
    [app: :scale30_erlang, version: "0.1.0", elixir: "~> 1.18", deps: deps(), elixirc_paths: ["ex"],
     escript: [main_module: Scale30.Adapter]]
  end

  def application, do: [extra_applications: [:crypto, :public_key]]

  defp deps, do: [{:jose, "== 1.11.12"}]
end
