defmodule Mix.Tasks.Multicodec.Gen do

  use Mix.Task

  @shortdoc "Given a source table (CSV file), generates an Elixir file containing multicodec metadata."

  @switches [
    output: :string
  ]

  @aliases [
    o: :output
  ]

  def run(args) do
    {options, input} = OptionParser.parse!(args, switches: @switches, aliases: @aliases)

    output = Keyword.get(options, :output, "lib/atproto")

    File.mkdir_p!(output)

    codecs =
      input
      |> File.stream!()
      |> Stream.map(&String.trim/1)
      |> Stream.map(fn line ->
        line
        |> String.split(",")
        |> Enum.map(&String.trim/1)
      end)
      |> Enum.reduce({nil, []}, fn
        header, {nil, _} ->
          {header, []}

        line, {header, acc} ->
          codec = Enum.zip(header, line) |> Enum.into(%{})
          {header, [codec | acc]}
      end)
      |> elem(1)
      |> Enum.sort_by(fn codec -> codec["code"] end)

    compendium = __DIR__
    |> Path.join("compendium.eex")
    |> EEx.eval_file(compendium: codecs)

    output
    |> Path.join("multicodec.ex")
    |> File.write!(compendium)
  end
end
