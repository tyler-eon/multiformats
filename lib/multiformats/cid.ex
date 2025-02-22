defmodule Multiformats.CID do
  @moduledoc """
  Handles encoding and decoding CIDs using the multiformats library.
  """

  alias Multiformats.{Multibase, Multicodec, Multihash}

  defstruct [
    cid: nil,
    version: nil,
    content_type: nil,
    content_address: nil,
    hash_algorithm: nil,
    hash_size: nil,
    hash_digest: nil
  ]

  @type t :: %__MODULE__{
    cid: binary(),
    version: non_neg_integer(),
    content_type: binary(),
    content_address: binary(),
    hash_algorithm: binary(),
    hash_size: non_neg_integer(),
    hash_digest: binary()
  }

  @doc """
  Decodes CID binary string into a CID struct.

  If the CID begins with the `identity` prefix (`0x00`), it is assumed to be a CIDv1 string with no multibase encoding.
  """
  @spec decode(binary()) :: t()
  def decode(cid) do
    if is_v0?(cid) do
      parse_v0(cid)
    else
      parse_v1(cid)
    end
  end

  @doc """
  Only CIDv0 has an explicit check because all subsequent CID versions are self-describing and therefore you can just pop the version number off the binary string.
  """
  @spec is_v0?(binary()) :: boolean()
  def is_v0?(cid), do: String.length(cid) == 46 and String.starts_with?(cid, "Qm")

  defp parse_v0(cid) do
    content_address = Multibase.Base58.decode!(cid)
    {algo, size, digest} = Multihash.decode(content_address)

    %__MODULE__{
      cid: cid,
      version: 0,
      content_type: "dag-pb",
      content_address: content_address,
      hash_algorithm: algo,
      hash_size: size,
      hash_digest: digest
    }
  end

  defp parse_v1(cid) do
    decoded_cid =
      case cid do
        << 0, rest :: binary >> ->
          rest
        _ ->
          Multibase.decode!(cid)
      end
    {:ok, {version, content_data}} = Multicodec.decode(decoded_cid)
    {:ok, {content_type, content_address}} = Multicodec.decode(content_data)
    {algo, size, digest} = Multihash.decode(content_address)

    %__MODULE__{
      cid: cid,
      version: parse_cid_version(version),
      content_type: content_type,
      content_address: content_address,
      hash_algorithm: algo,
      hash_size: size,
      hash_digest: digest
    }
  end

  defp parse_cid_version("cidv" <> version), do: String.to_integer(version)

  @doc """
  Encodes binary content into a CIDv0 binary string. This assumes the type of the content is `dag-pb`, uses the `sha2-256` hashing algorithm, and is `base58btc` encoded (but without the `z` prefix).
  """
  def encode_v0(content) do
    content
    |> Multihash.encode!("sha2-256")
    |> Multibase.Base58.encode()
  end

  @doc """
  Encodes binary content into a CIDv1 binary string. You control the descriptors and algorithms via the `opts` Keyword list argument.

  By default (i.e. when `opts` is not given), the following values are used by default:

  - `:content_type` is set to `"raw"`
  - `:hash_algorithm` is set to `"sha2-256"`
  - `:base` is set to `:base32`
  """
  @spec encode(binary(), Keyword.t()) :: binary()
  def encode(content, opts \\ []) do
    content_type = Keyword.get(opts, :content_type, "raw")
    hash_algorithm = Keyword.get(opts, :hash_algorithm, "sha2-256")
    base = Keyword.get(opts, :base, :base32)

    content
    |> Multihash.encode!(hash_algorithm)
    |> Multicodec.encode!(content_type)
    |> Multicodec.encode!("cidv1")
    |> Multibase.encode(base)
  end
end
