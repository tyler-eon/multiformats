defmodule Multiformats.MixProject do
  use Mix.Project

  def project do
    [
      app: :multiformats_ex,
      version: "0.2.0",
      elixir: "~> 1.18",
      description: "A collection of Elixir modules for working with the multiformats ecosystem.",
      package: package(),
      deps: deps()
    ]
  end

  def package do
    [
      name: "multiformats_ex",
      maintainers: ["Tyler Eon"],
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/tyler-eon/multiformats"
      }
    ]
  end

  defp deps do
    [
      {:varint, "~> 1.4"},
      {:ex_doc, ">= 0.0.0", only: :dev, runtime: false}
    ]
  end
end
