defmodule Multiformats.Multihash do
  @moduledoc """
  Handles encoding and decoding multihash binary data, as specified by [multiformats](https://github.com/multiformats/multihash).
  """

  alias Multiformats.{Multibase, Multicodec, Multihash}

  @doc """
  Decodes multihash binary data into a tuple of the hash type, digest size, and digest binary.

  Can pass an option to `:base` to encode the digest binary into a different format using multibase. Any base supported by `Multibase.encode/2` can be used here, otherwise you will receive an error.
  """
  def decode(data, opts \\ []) do
    {:ok, {hash, content}} = Multicodec.decode(data)
    {size, digest} = Varint.LEB128.decode(content)
    case Keyword.get(opts, :base) do
      nil -> {hash, size, digest}
      base -> {hash, size, Multibase.encode(digest, base)}
    end
  end

  def encode(data, hash_algorithm) do
    digest = hash(data, hash_algorithm)
    size = byte_size(digest)
    Multicodec.encode(<< size, digest :: binary >>, hash_algorithm)
  end

  def encode!(data, hash_algorithm) do
    {:ok, result} = encode(data, hash_algorithm)
    result
  end

  algo_map = %{
    "blake2b-512" => :blake2b,
    "blake2s-256" => :blake2s,
    "md4" => :md4,
    "md5" => :md5,
    "sha1" => :sha,
    "sha2-256" => :sha256,
    "sha2-384" => :sha384,
    "sha2-512" => :sha512,
    "sha3-224" => :sha3_224,
    "sha3-256" => :sha3_256,
    "sha3-384" => :sha3_384,
    "sha3-512" => :sha3_512,
    "sha2-256-trunc254-padded" => {Multihash.SHA256Trunc254Padded, []},
    "identity" => {Multihash.Identity, []}
  }

  for {name, fun} <- algo_map do
    case fun do
      algo when is_atom(algo) ->
  defp hash(data, unquote(name)), do: :crypto.hash(unquote(algo), data)
      {module, _opts} ->
  defp hash(data, unquote(name)), do: unquote(module).encode(data)
    end
  end

  defp hash(_, hash_algorithm), do: raise(ArgumentError, "Unsupported hash algorithm: #{hash_algorithm}")
end
