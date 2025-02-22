defmodule Multiformats.Multibase do
  @moduledoc """
  Multibase is a protocol for disambiguating the "base encoding" used to express binary data in text formats, as specified by [multiformats](https://github.com/multiformats/multibase).

  *Note*: Not all "official" multibase encodings are implemented here. Only those marked as "final" are guaranteed to be present.
  """

  alias Multiformats.Multibase.{Base16, Base32, Base36, Base58, Base64}

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  Encodes binary data using a supported multibase encoding.
  """
  @spec encode(binary(), atom()) :: binary()
  def encode(data, :base16), do: "f" <> Base16.encode(data, case: :lower)
  def encode(data, :base16upper), do: "F" <> Base16.encode(data, case: :upper)
  def encode(data, :base32), do: "b" <> Base32.encode(data, case: :lower, padding: false)
  def encode(data, :base32upper), do: "B" <> Base32.encode(data, case: :upper, padding: false)
  def encode(data, :base32pad), do: "c" <> Base32.encode(data, case: :lower, padding: true)
  def encode(data, :base32padupper), do: "C" <> Base32.encode(data, case: :upper, padding: true)
  #def encode(data, :base32z), do: "h" <> Base32.encode(data)
  def encode(data, :base36), do: "k" <> Base36.encode(data)
  #def encode(data, :base36upper), do: "K" <> Base36.encode(data, case: :upper)
  #def encode(data, :base45), do: "R" <> Base45.encode(data)
  def encode(data, :base58btc), do: "z" <> Base58.encode(data)
  def encode(data, :base58flickr), do: "Z" <> Base58.encode(data)
  def encode(data, :base64), do: "m" <> Base64.encode(data, padding: false)
  def encode(data, :base64pad), do: "M" <> Base64.encode(data, padding: true)
  def encode(data, :base64url), do: "u" <> Base64.encode(data, padding: false)
  def encode(data, :base64urlpad), do: "U" <> Base64.encode(data, padding: true)
  #def encode(data, :proquint), do: "p" <> Proquint.encode(data)
  #def encode(data, :base256emoji), do: "🚀" <> Base256.encode(data)

  @doc """
  Attempts to decode a binary string.
  """
  @spec decode(binary(), any()) :: {:ok, binary()} | {:error, Error.t()}
  def decode(data, _opts \\ []) do
    {:ok, decode!(data)}
  rescue
    error ->
      {:error, error}
  end


  @doc """
  Decodes a multibase-encoded string. This will not return information about the encoding used, just the decoded binary data.
  """
  @spec decode!(binary(), any()) :: binary()
  def decode!(data, _opts \\ [])
  def decode!("f" <> data, _opts), do: Base16.decode!(data, case: :lower)
  def decode!("F" <> data, _opts), do: Base16.decode!(data, case: :upper)
  def decode!("b" <> data, _opts), do: Base32.decode!(data, case: :lower, padding: false)
  def decode!("B" <> data, _opts), do: Base32.decode!(data, case: :upper, padding: false)
  def decode!("c" <> data, _opts), do: Base32.decode!(data, case: :lower, padding: true)
  def decode!("C" <> data, _opts), do: Base32.decode!(data, case: :upper, padding: true)
  #def decode!("h" <> data, _opts), do: Base32.decode!(data)
  def decode!("k" <> data, _opts), do: Base36.decode!(data)
  #def decode!("K" <> data, _opts), do: Base36.decode!(data, case: :upper)
  #def decode!("R" <> data, _opts), do: Base45.decode!(data)
  def decode!("z" <> data, _opts), do: Base58.decode!(data)
  def decode!("Z" <> data, _opts), do: Base58.decode!(data)
  def decode!("m" <> data, _opts), do: Base64.decode!(data, padding: false)
  def decode!("M" <> data, _opts), do: Base64.decode!(data, padding: true)
  def decode!("u" <> data, _opts), do: Base64.decode!(data, padding: false)
  def decode!("U" <> data, _opts), do: Base64.decode!(data, padding: true)
  #def decode!("p" <> data, _opts), do: Proquint.decode!(data)
  #def decode!("🚀" <> data, _opts), do: Base256.encode(data)
end
