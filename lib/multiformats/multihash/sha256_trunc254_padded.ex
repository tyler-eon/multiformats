defmodule Multiformats.Multihash.SHA256Trunc254Padded do
  @moduledoc """
  The "sha2-256-trunc254-padded" multihash algorithm is a variant of SHA-256 that replaces the most significant 2 bits of the last byte with zeroes.
  """

  use Multiformats.Multicodec.Codec, multihash: true

  import Bitwise

  @impl true
  def encode(data, _), do: :crypto.hash(:sha256, data) |> trunc254()

  # A sha256 hash is always 32 bytes long.
  # We need to band the last 2 bits of the last byte in the binary.
  defp trunc254(<<head::binary-size(31), last::binary-size(1)>>) do
    truncated =
      last
      |> :binary.decode_unsigned()
      |> band(0b11111110)
      |> :binary.encode_unsigned()

    <<head::binary, truncated::binary-size(1)>>
  end
end
