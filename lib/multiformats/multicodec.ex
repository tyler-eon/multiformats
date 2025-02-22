defmodule Multiformats.Multicodec do
  @moduledoc """
  The primary module for fetching multicodec metadata.

  Data *should be* generated from [this source table](https://github.com/multiformats/multicodec/blob/master/table.csv). However, the task to generate this source file accepts any appropriately-formatted CSV file, allowing for custom codecs to be used if desired.
  """

  @doc """
  Encodes binary data using a codec. The codec can either be the name of the codec or the numeric representation of the codec. A numeric representation is either an integer, e.g. a codepoint or hex value, or a bitstring.
  """
  @spec encode(binary(), integer() | binary()) :: {:ok, binary()} | :error
  def encode(data, codec) when is_binary(data) do
    case get(codec) do
      nil -> :error
      # Note: The prefix in the metadata is already encoded as a varint (LEB128).
      # For this reason, we do not need to encode the prefix again and can use it as-is.
      %{prefix: prefix} -> {:ok, prefix <> data}
    end
  end

  @doc """
  Similar to `encode/2`, but raises an error if the codec is not supported.
  """
  @spec encode!(binary(), integer() | binary()) :: binary()
  def encode!(data, codec) do
    {:ok, result} = encode(data, codec)
    result
  end

  @doc """
  Decodes binary data into the codec *name* and the embedded data.

  For example, if the binary data is prefixed with `<<22>>` then the codec name returned will be `"sha3-256"`.

      # On a successful decode, the second element is a tuple containing the codec name and associated binary data.
      {:ok, {"sha3-256", data}} = decode(<<22, ...>>)

  Possible errors can occur from either an unknown codec, i.e. the prefix did not match any known codec, or the binary data was not properly varint-encoded.
  """
  @spec decode(binary()) :: {:ok, {String.t(), binary()}} | {:error, any()}
  def decode(data) when is_binary(data) do
    {prefix, data} = Varint.LEB128.decode(data)
    case get(prefix) do
      nil -> {:error, :unknown_codec}
      %{name: codec} -> {:ok, {codec, data}}
    end
  rescue
    _ -> {:error, :invalid_leb128_integer}
  end


  @doc """
  Get a codec by either the integer/hex value or the human-readable name.
  """
  @spec get(integer()) :: map() | nil
  
  def get(0x00), do: %{
    code: 0x00,
    prefix: <<0>>,
    name: "identity",
    description: "raw binary",
    status: "permanent",
    tag: "multihash"
  }
  def get("identity"), do: get(0x00)
  
  def get(0x01), do: %{
    code: 0x01,
    prefix: <<1>>,
    name: "cidv1",
    description: "CIDv1",
    status: "permanent",
    tag: "cid"
  }
  def get("cidv1"), do: get(0x01)
  
  def get(0x0111), do: %{
    code: 0x0111,
    prefix: <<145, 2>>,
    name: "udp",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("udp"), do: get(0x0111)
  
  def get(0x0113), do: %{
    code: 0x0113,
    prefix: <<147, 2>>,
    name: "p2p-webrtc-star",
    description: "Use webrtc or webrtc-direct instead",
    status: "deprecated",
    tag: "multiaddr"
  }
  def get("p2p-webrtc-star"), do: get(0x0113)
  
  def get(0x0114), do: %{
    code: 0x0114,
    prefix: <<148, 2>>,
    name: "p2p-webrtc-direct",
    description: "Use webrtc or webrtc-direct instead",
    status: "deprecated",
    tag: "multiaddr"
  }
  def get("p2p-webrtc-direct"), do: get(0x0114)
  
  def get(0x0115), do: %{
    code: 0x0115,
    prefix: <<149, 2>>,
    name: "p2p-stardust",
    description: "",
    status: "deprecated",
    tag: "multiaddr"
  }
  def get("p2p-stardust"), do: get(0x0115)
  
  def get(0x0118), do: %{
    code: 0x0118,
    prefix: <<152, 2>>,
    name: "webrtc-direct",
    description: "ICE-lite webrtc transport with SDP munging during connection establishment and without use of a STUN server",
    status: "draft",
    tag: "multiaddr"
  }
  def get("webrtc-direct"), do: get(0x0118)
  
  def get(0x0119), do: %{
    code: 0x0119,
    prefix: <<153, 2>>,
    name: "webrtc",
    description: "webrtc transport where connection establishment is according to w3c spec",
    status: "draft",
    tag: "multiaddr"
  }
  def get("webrtc"), do: get(0x0119)
  
  def get(0x0122), do: %{
    code: 0x0122,
    prefix: <<162, 2>>,
    name: "p2p-circuit",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("p2p-circuit"), do: get(0x0122)
  
  def get(0x0129), do: %{
    code: 0x0129,
    prefix: <<169, 2>>,
    name: "dag-json",
    description: "MerkleDAG json",
    status: "permanent",
    tag: "ipld"
  }
  def get("dag-json"), do: get(0x0129)
  
  def get(0x012d), do: %{
    code: 0x012d,
    prefix: <<173, 2>>,
    name: "udt",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("udt"), do: get(0x012d)
  
  def get(0x012e), do: %{
    code: 0x012e,
    prefix: <<174, 2>>,
    name: "utp",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("utp"), do: get(0x012e)
  
  def get(0x0132), do: %{
    code: 0x0132,
    prefix: <<178, 2>>,
    name: "crc32",
    description: "CRC-32 non-cryptographic hash algorithm (IEEE 802.3)",
    status: "draft",
    tag: "hash"
  }
  def get("crc32"), do: get(0x0132)
  
  def get(0x0164), do: %{
    code: 0x0164,
    prefix: <<228, 2>>,
    name: "crc64-ecma",
    description: "CRC-64 non-cryptographic hash algorithm (ECMA-182 - Annex B)",
    status: "draft",
    tag: "hash"
  }
  def get("crc64-ecma"), do: get(0x0164)
  
  def get(0x0190), do: %{
    code: 0x0190,
    prefix: <<144, 3>>,
    name: "unix",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("unix"), do: get(0x0190)
  
  def get(0x0196), do: %{
    code: 0x0196,
    prefix: <<150, 3>>,
    name: "thread",
    description: "Textile Thread",
    status: "draft",
    tag: "multiaddr"
  }
  def get("thread"), do: get(0x0196)
  
  def get(0x01a5), do: %{
    code: 0x01a5,
    prefix: <<165, 3>>,
    name: "p2p",
    description: "libp2p",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("p2p"), do: get(0x01a5)
  
  def get(0x01bb), do: %{
    code: 0x01bb,
    prefix: <<187, 3>>,
    name: "https",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("https"), do: get(0x01bb)
  
  def get(0x01bc), do: %{
    code: 0x01bc,
    prefix: <<188, 3>>,
    name: "onion",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("onion"), do: get(0x01bc)
  
  def get(0x01bd), do: %{
    code: 0x01bd,
    prefix: <<189, 3>>,
    name: "onion3",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("onion3"), do: get(0x01bd)
  
  def get(0x01be), do: %{
    code: 0x01be,
    prefix: <<190, 3>>,
    name: "garlic64",
    description: "I2P base64 (raw public key)",
    status: "draft",
    tag: "multiaddr"
  }
  def get("garlic64"), do: get(0x01be)
  
  def get(0x01bf), do: %{
    code: 0x01bf,
    prefix: <<191, 3>>,
    name: "garlic32",
    description: "I2P base32 (hashed public key or encoded public key/checksum+optional secret)",
    status: "draft",
    tag: "multiaddr"
  }
  def get("garlic32"), do: get(0x01bf)
  
  def get(0x01c0), do: %{
    code: 0x01c0,
    prefix: <<192, 3>>,
    name: "tls",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("tls"), do: get(0x01c0)
  
  def get(0x01c1), do: %{
    code: 0x01c1,
    prefix: <<193, 3>>,
    name: "sni",
    description: "Server Name Indication RFC 6066 § 3",
    status: "draft",
    tag: "multiaddr"
  }
  def get("sni"), do: get(0x01c1)
  
  def get(0x01c6), do: %{
    code: 0x01c6,
    prefix: <<198, 3>>,
    name: "noise",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("noise"), do: get(0x01c6)
  
  def get(0x01c8), do: %{
    code: 0x01c8,
    prefix: <<200, 3>>,
    name: "shs",
    description: "Secure Scuttlebutt - Secret Handshake Stream",
    status: "draft",
    tag: "multiaddr"
  }
  def get("shs"), do: get(0x01c8)
  
  def get(0x01cc), do: %{
    code: 0x01cc,
    prefix: <<204, 3>>,
    name: "quic",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("quic"), do: get(0x01cc)
  
  def get(0x01cd), do: %{
    code: 0x01cd,
    prefix: <<205, 3>>,
    name: "quic-v1",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("quic-v1"), do: get(0x01cd)
  
  def get(0x01d1), do: %{
    code: 0x01d1,
    prefix: <<209, 3>>,
    name: "webtransport",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("webtransport"), do: get(0x01d1)
  
  def get(0x01d2), do: %{
    code: 0x01d2,
    prefix: <<210, 3>>,
    name: "certhash",
    description: "TLS certificate's fingerprint as a multihash",
    status: "draft",
    tag: "multiaddr"
  }
  def get("certhash"), do: get(0x01d2)
  
  def get(0x01dd), do: %{
    code: 0x01dd,
    prefix: <<221, 3>>,
    name: "ws",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("ws"), do: get(0x01dd)
  
  def get(0x01de), do: %{
    code: 0x01de,
    prefix: <<222, 3>>,
    name: "wss",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("wss"), do: get(0x01de)
  
  def get(0x01df), do: %{
    code: 0x01df,
    prefix: <<223, 3>>,
    name: "p2p-websocket-star",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("p2p-websocket-star"), do: get(0x01df)
  
  def get(0x01e0), do: %{
    code: 0x01e0,
    prefix: <<224, 3>>,
    name: "http",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("http"), do: get(0x01e0)
  
  def get(0x01e1), do: %{
    code: 0x01e1,
    prefix: <<225, 3>>,
    name: "http-path",
    description: "Percent-encoded path to an HTTP resource",
    status: "draft",
    tag: "multiaddr"
  }
  def get("http-path"), do: get(0x01e1)
  
  def get(0x01f0), do: %{
    code: 0x01f0,
    prefix: <<240, 3>>,
    name: "swhid-1-snp",
    description: "SoftWare Heritage persistent IDentifier version 1 snapshot",
    status: "draft",
    tag: "ipld"
  }
  def get("swhid-1-snp"), do: get(0x01f0)
  
  def get(0x02), do: %{
    code: 0x02,
    prefix: <<2>>,
    name: "cidv2",
    description: "CIDv2",
    status: "draft",
    tag: "cid"
  }
  def get("cidv2"), do: get(0x02)
  
  def get(0x0200), do: %{
    code: 0x0200,
    prefix: <<128, 4>>,
    name: "json",
    description: "JSON (UTF-8-encoded)",
    status: "permanent",
    tag: "ipld"
  }
  def get("json"), do: get(0x0200)
  
  def get(0x0201), do: %{
    code: 0x0201,
    prefix: <<129, 4>>,
    name: "messagepack",
    description: "MessagePack",
    status: "draft",
    tag: "serialization"
  }
  def get("messagepack"), do: get(0x0201)
  
  def get(0x0202), do: %{
    code: 0x0202,
    prefix: <<130, 4>>,
    name: "car",
    description: "Content Addressable aRchive (CAR)",
    status: "draft",
    tag: "serialization"
  }
  def get("car"), do: get(0x0202)
  
  def get(0x03), do: %{
    code: 0x03,
    prefix: <<3>>,
    name: "cidv3",
    description: "CIDv3",
    status: "draft",
    tag: "cid"
  }
  def get("cidv3"), do: get(0x03)
  
  def get(0x0300), do: %{
    code: 0x0300,
    prefix: <<128, 6>>,
    name: "ipns-record",
    description: "Signed IPNS Record",
    status: "permanent",
    tag: "serialization"
  }
  def get("ipns-record"), do: get(0x0300)
  
  def get(0x0301), do: %{
    code: 0x0301,
    prefix: <<129, 6>>,
    name: "libp2p-peer-record",
    description: "libp2p peer record type",
    status: "permanent",
    tag: "libp2p"
  }
  def get("libp2p-peer-record"), do: get(0x0301)
  
  def get(0x0302), do: %{
    code: 0x0302,
    prefix: <<130, 6>>,
    name: "libp2p-relay-rsvp",
    description: "libp2p relay reservation voucher",
    status: "permanent",
    tag: "libp2p"
  }
  def get("libp2p-relay-rsvp"), do: get(0x0302)
  
  def get(0x0309), do: %{
    code: 0x0309,
    prefix: <<137, 6>>,
    name: "memorytransport",
    description: "in memory transport for self-dialing and testing; arbitrary",
    status: "permanent",
    tag: "libp2p"
  }
  def get("memorytransport"), do: get(0x0309)
  
  def get(0x04), do: %{
    code: 0x04,
    prefix: <<4>>,
    name: "ip4",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("ip4"), do: get(0x04)
  
  def get(0x0400), do: %{
    code: 0x0400,
    prefix: <<128, 8>>,
    name: "car-index-sorted",
    description: "CARv2 IndexSorted index format",
    status: "draft",
    tag: "serialization"
  }
  def get("car-index-sorted"), do: get(0x0400)
  
  def get(0x0401), do: %{
    code: 0x0401,
    prefix: <<129, 8>>,
    name: "car-multihash-index-sorted",
    description: "CARv2 MultihashIndexSorted index format",
    status: "draft",
    tag: "serialization"
  }
  def get("car-multihash-index-sorted"), do: get(0x0401)
  
  def get(0x06), do: %{
    code: 0x06,
    prefix: <<6>>,
    name: "tcp",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("tcp"), do: get(0x06)
  
  def get(0x0900), do: %{
    code: 0x0900,
    prefix: <<128, 18>>,
    name: "transport-bitswap",
    description: "Bitswap datatransfer",
    status: "draft",
    tag: "transport"
  }
  def get("transport-bitswap"), do: get(0x0900)
  
  def get(0x0910), do: %{
    code: 0x0910,
    prefix: <<144, 18>>,
    name: "transport-graphsync-filecoinv1",
    description: "Filecoin graphsync datatransfer",
    status: "draft",
    tag: "transport"
  }
  def get("transport-graphsync-filecoinv1"), do: get(0x0910)
  
  def get(0x0920), do: %{
    code: 0x0920,
    prefix: <<160, 18>>,
    name: "transport-ipfs-gateway-http",
    description: "HTTP IPFS Gateway trustless datatransfer",
    status: "draft",
    tag: "transport"
  }
  def get("transport-ipfs-gateway-http"), do: get(0x0920)
  
  def get(0x0d1d), do: %{
    code: 0x0d1d,
    prefix: <<157, 26>>,
    name: "multidid",
    description: "Compact encoding for Decentralized Identifers",
    status: "draft",
    tag: "multiformat"
  }
  def get("multidid"), do: get(0x0d1d)
  
  def get(0x1012), do: %{
    code: 0x1012,
    prefix: <<146, 32>>,
    name: "sha2-256-trunc254-padded",
    description: "SHA2-256 with the two most significant bits from the last byte zeroed (as via a mask with 0b00111111) - used for proving trees as in Filecoin",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-256-trunc254-padded"), do: get(0x1012)
  
  def get(0x1013), do: %{
    code: 0x1013,
    prefix: <<147, 32>>,
    name: "sha2-224",
    description: "aka SHA-224; as specified by FIPS 180-4.",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-224"), do: get(0x1013)
  
  def get(0x1014), do: %{
    code: 0x1014,
    prefix: <<148, 32>>,
    name: "sha2-512-224",
    description: "aka SHA-512/224; as specified by FIPS 180-4.",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-512-224"), do: get(0x1014)
  
  def get(0x1015), do: %{
    code: 0x1015,
    prefix: <<149, 32>>,
    name: "sha2-512-256",
    description: "aka SHA-512/256; as specified by FIPS 180-4.",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-512-256"), do: get(0x1015)
  
  def get(0x1022), do: %{
    code: 0x1022,
    prefix: <<162, 32>>,
    name: "murmur3-x64-128",
    description: "",
    status: "draft",
    tag: "hash"
  }
  def get("murmur3-x64-128"), do: get(0x1022)
  
  def get(0x1052), do: %{
    code: 0x1052,
    prefix: <<210, 32>>,
    name: "ripemd-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("ripemd-128"), do: get(0x1052)
  
  def get(0x1053), do: %{
    code: 0x1053,
    prefix: <<211, 32>>,
    name: "ripemd-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("ripemd-160"), do: get(0x1053)
  
  def get(0x1054), do: %{
    code: 0x1054,
    prefix: <<212, 32>>,
    name: "ripemd-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("ripemd-256"), do: get(0x1054)
  
  def get(0x1055), do: %{
    code: 0x1055,
    prefix: <<213, 32>>,
    name: "ripemd-320",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("ripemd-320"), do: get(0x1055)
  
  def get(0x11), do: %{
    code: 0x11,
    prefix: <<17>>,
    name: "sha1",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha1"), do: get(0x11)
  
  def get(0x1100), do: %{
    code: 0x1100,
    prefix: <<128, 34>>,
    name: "x11",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("x11"), do: get(0x1100)
  
  def get(0x12), do: %{
    code: 0x12,
    prefix: <<18>>,
    name: "sha2-256",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-256"), do: get(0x12)
  
  def get(0x1200), do: %{
    code: 0x1200,
    prefix: <<128, 36>>,
    name: "p256-pub",
    description: "P-256 public Key (compressed)",
    status: "draft",
    tag: "key"
  }
  def get("p256-pub"), do: get(0x1200)
  
  def get(0x1201), do: %{
    code: 0x1201,
    prefix: <<129, 36>>,
    name: "p384-pub",
    description: "P-384 public Key (compressed)",
    status: "draft",
    tag: "key"
  }
  def get("p384-pub"), do: get(0x1201)
  
  def get(0x1202), do: %{
    code: 0x1202,
    prefix: <<130, 36>>,
    name: "p521-pub",
    description: "P-521 public Key (compressed)",
    status: "draft",
    tag: "key"
  }
  def get("p521-pub"), do: get(0x1202)
  
  def get(0x1203), do: %{
    code: 0x1203,
    prefix: <<131, 36>>,
    name: "ed448-pub",
    description: "Ed448 public Key",
    status: "draft",
    tag: "key"
  }
  def get("ed448-pub"), do: get(0x1203)
  
  def get(0x1204), do: %{
    code: 0x1204,
    prefix: <<132, 36>>,
    name: "x448-pub",
    description: "X448 public Key",
    status: "draft",
    tag: "key"
  }
  def get("x448-pub"), do: get(0x1204)
  
  def get(0x1205), do: %{
    code: 0x1205,
    prefix: <<133, 36>>,
    name: "rsa-pub",
    description: "RSA public key. DER-encoded ASN.1 type RSAPublicKey according to IETF RFC 8017 (PKCS #1)",
    status: "draft",
    tag: "key"
  }
  def get("rsa-pub"), do: get(0x1205)
  
  def get(0x1206), do: %{
    code: 0x1206,
    prefix: <<134, 36>>,
    name: "sm2-pub",
    description: "SM2 public key (compressed)",
    status: "draft",
    tag: "key"
  }
  def get("sm2-pub"), do: get(0x1206)
  
  def get(0x1207), do: %{
    code: 0x1207,
    prefix: <<135, 36>>,
    name: "vlad",
    description: "Verifiable Long-lived ADdress",
    status: "draft",
    tag: "vlad"
  }
  def get("vlad"), do: get(0x1207)
  
  def get(0x1208), do: %{
    code: 0x1208,
    prefix: <<136, 36>>,
    name: "provenance-log",
    description: "Verifiable and permissioned append-only log",
    status: "draft",
    tag: "serialization"
  }
  def get("provenance-log"), do: get(0x1208)
  
  def get(0x1209), do: %{
    code: 0x1209,
    prefix: <<137, 36>>,
    name: "provenance-log-entry",
    description: "Verifiable and permissioned append-only log entry",
    status: "draft",
    tag: "serialization"
  }
  def get("provenance-log-entry"), do: get(0x1209)
  
  def get(0x120a), do: %{
    code: 0x120a,
    prefix: <<138, 36>>,
    name: "provenance-log-script",
    description: "Verifiable and permissioned append-only log script",
    status: "draft",
    tag: "serialization"
  }
  def get("provenance-log-script"), do: get(0x120a)
  
  def get(0x120b), do: %{
    code: 0x120b,
    prefix: <<139, 36>>,
    name: "mlkem-512-pub",
    description: "ML-KEM 512 public key; as specified by FIPS 203",
    status: "draft",
    tag: "key"
  }
  def get("mlkem-512-pub"), do: get(0x120b)
  
  def get(0x120c), do: %{
    code: 0x120c,
    prefix: <<140, 36>>,
    name: "mlkem-768-pub",
    description: "ML-KEM 768 public key; as specified by FIPS 203",
    status: "draft",
    tag: "key"
  }
  def get("mlkem-768-pub"), do: get(0x120c)
  
  def get(0x120d), do: %{
    code: 0x120d,
    prefix: <<141, 36>>,
    name: "mlkem-1024-pub",
    description: "ML-KEM 1024 public key; as specified by FIPS 203",
    status: "draft",
    tag: "key"
  }
  def get("mlkem-1024-pub"), do: get(0x120d)
  
  def get(0x1239), do: %{
    code: 0x1239,
    prefix: <<185, 36>>,
    name: "multisig",
    description: "Digital signature multiformat",
    status: "draft",
    tag: "multiformat"
  }
  def get("multisig"), do: get(0x1239)
  
  def get(0x123a), do: %{
    code: 0x123a,
    prefix: <<186, 36>>,
    name: "multikey",
    description: "Encryption key multiformat",
    status: "draft",
    tag: "multiformat"
  }
  def get("multikey"), do: get(0x123a)
  
  def get(0x123b), do: %{
    code: 0x123b,
    prefix: <<187, 36>>,
    name: "nonce",
    description: "Nonce random value",
    status: "draft",
    tag: "nonce"
  }
  def get("nonce"), do: get(0x123b)
  
  def get(0x13), do: %{
    code: 0x13,
    prefix: <<19>>,
    name: "sha2-512",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-512"), do: get(0x13)
  
  def get(0x1300), do: %{
    code: 0x1300,
    prefix: <<128, 38>>,
    name: "ed25519-priv",
    description: "Ed25519 private key",
    status: "draft",
    tag: "key"
  }
  def get("ed25519-priv"), do: get(0x1300)
  
  def get(0x1301), do: %{
    code: 0x1301,
    prefix: <<129, 38>>,
    name: "secp256k1-priv",
    description: "Secp256k1 private key",
    status: "draft",
    tag: "key"
  }
  def get("secp256k1-priv"), do: get(0x1301)
  
  def get(0x1302), do: %{
    code: 0x1302,
    prefix: <<130, 38>>,
    name: "x25519-priv",
    description: "Curve25519 private key",
    status: "draft",
    tag: "key"
  }
  def get("x25519-priv"), do: get(0x1302)
  
  def get(0x1303), do: %{
    code: 0x1303,
    prefix: <<131, 38>>,
    name: "sr25519-priv",
    description: "Sr25519 private key",
    status: "draft",
    tag: "key"
  }
  def get("sr25519-priv"), do: get(0x1303)
  
  def get(0x1305), do: %{
    code: 0x1305,
    prefix: <<133, 38>>,
    name: "rsa-priv",
    description: "RSA private key",
    status: "draft",
    tag: "key"
  }
  def get("rsa-priv"), do: get(0x1305)
  
  def get(0x1306), do: %{
    code: 0x1306,
    prefix: <<134, 38>>,
    name: "p256-priv",
    description: "P-256 private key",
    status: "draft",
    tag: "key"
  }
  def get("p256-priv"), do: get(0x1306)
  
  def get(0x1307), do: %{
    code: 0x1307,
    prefix: <<135, 38>>,
    name: "p384-priv",
    description: "P-384 private key",
    status: "draft",
    tag: "key"
  }
  def get("p384-priv"), do: get(0x1307)
  
  def get(0x1308), do: %{
    code: 0x1308,
    prefix: <<136, 38>>,
    name: "p521-priv",
    description: "P-521 private key",
    status: "draft",
    tag: "key"
  }
  def get("p521-priv"), do: get(0x1308)
  
  def get(0x1309), do: %{
    code: 0x1309,
    prefix: <<137, 38>>,
    name: "bls12_381-g1-priv",
    description: "BLS12-381 G1 private key",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1-priv"), do: get(0x1309)
  
  def get(0x130a), do: %{
    code: 0x130a,
    prefix: <<138, 38>>,
    name: "bls12_381-g2-priv",
    description: "BLS12-381 G2 private key",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g2-priv"), do: get(0x130a)
  
  def get(0x130b), do: %{
    code: 0x130b,
    prefix: <<139, 38>>,
    name: "bls12_381-g1g2-priv",
    description: "BLS12-381 G1 and G2 private key",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1g2-priv"), do: get(0x130b)
  
  def get(0x130c), do: %{
    code: 0x130c,
    prefix: <<140, 38>>,
    name: "bls12_381-g1-pub-share",
    description: "BLS12-381 G1 public key share",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1-pub-share"), do: get(0x130c)
  
  def get(0x130d), do: %{
    code: 0x130d,
    prefix: <<141, 38>>,
    name: "bls12_381-g2-pub-share",
    description: "BLS12-381 G2 public key share",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g2-pub-share"), do: get(0x130d)
  
  def get(0x130e), do: %{
    code: 0x130e,
    prefix: <<142, 38>>,
    name: "bls12_381-g1-priv-share",
    description: "BLS12-381 G1 private key share",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1-priv-share"), do: get(0x130e)
  
  def get(0x130f), do: %{
    code: 0x130f,
    prefix: <<143, 38>>,
    name: "bls12_381-g2-priv-share",
    description: "BLS12-381 G2 private key share",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g2-priv-share"), do: get(0x130f)
  
  def get(0x1310), do: %{
    code: 0x1310,
    prefix: <<144, 38>>,
    name: "sm2-priv",
    description: "SM2 private key",
    status: "draft",
    tag: "key"
  }
  def get("sm2-priv"), do: get(0x1310)
  
  def get(0x14), do: %{
    code: 0x14,
    prefix: <<20>>,
    name: "sha3-512",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha3-512"), do: get(0x14)
  
  def get(0x15), do: %{
    code: 0x15,
    prefix: <<21>>,
    name: "sha3-384",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha3-384"), do: get(0x15)
  
  def get(0x16), do: %{
    code: 0x16,
    prefix: <<22>>,
    name: "sha3-256",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha3-256"), do: get(0x16)
  
  def get(0x17), do: %{
    code: 0x17,
    prefix: <<23>>,
    name: "sha3-224",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha3-224"), do: get(0x17)
  
  def get(0x18), do: %{
    code: 0x18,
    prefix: <<24>>,
    name: "shake-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("shake-128"), do: get(0x18)
  
  def get(0x19), do: %{
    code: 0x19,
    prefix: <<25>>,
    name: "shake-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("shake-256"), do: get(0x19)
  
  def get(0x1a), do: %{
    code: 0x1a,
    prefix: <<26>>,
    name: "keccak-224",
    description: "keccak has variable output length. The number specifies the core length",
    status: "draft",
    tag: "multihash"
  }
  def get("keccak-224"), do: get(0x1a)
  
  def get(0x1a14), do: %{
    code: 0x1a14,
    prefix: <<148, 52>>,
    name: "lamport-sha3-512-pub",
    description: "Lamport public key based on SHA3-512",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-512-pub"), do: get(0x1a14)
  
  def get(0x1a15), do: %{
    code: 0x1a15,
    prefix: <<149, 52>>,
    name: "lamport-sha3-384-pub",
    description: "Lamport public key based on SHA3-384",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-384-pub"), do: get(0x1a15)
  
  def get(0x1a16), do: %{
    code: 0x1a16,
    prefix: <<150, 52>>,
    name: "lamport-sha3-256-pub",
    description: "Lamport public key based on SHA3-256",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-256-pub"), do: get(0x1a16)
  
  def get(0x1a24), do: %{
    code: 0x1a24,
    prefix: <<164, 52>>,
    name: "lamport-sha3-512-priv",
    description: "Lamport private key based on SHA3-512",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-512-priv"), do: get(0x1a24)
  
  def get(0x1a25), do: %{
    code: 0x1a25,
    prefix: <<165, 52>>,
    name: "lamport-sha3-384-priv",
    description: "Lamport private key based on SHA3-384",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-384-priv"), do: get(0x1a25)
  
  def get(0x1a26), do: %{
    code: 0x1a26,
    prefix: <<166, 52>>,
    name: "lamport-sha3-256-priv",
    description: "Lamport private key based on SHA3-256",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-256-priv"), do: get(0x1a26)
  
  def get(0x1a34), do: %{
    code: 0x1a34,
    prefix: <<180, 52>>,
    name: "lamport-sha3-512-priv-share",
    description: "Lamport private key share based on SHA3-512 and split with Shamir gf256",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-512-priv-share"), do: get(0x1a34)
  
  def get(0x1a35), do: %{
    code: 0x1a35,
    prefix: <<181, 52>>,
    name: "lamport-sha3-384-priv-share",
    description: "Lamport private key share based on SHA3-384 and split with Shamir gf256",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-384-priv-share"), do: get(0x1a35)
  
  def get(0x1a36), do: %{
    code: 0x1a36,
    prefix: <<182, 52>>,
    name: "lamport-sha3-256-priv-share",
    description: "Lamport private key share based on SHA3-256 and split with Shamir gf256",
    status: "draft",
    tag: "key"
  }
  def get("lamport-sha3-256-priv-share"), do: get(0x1a36)
  
  def get(0x1a44), do: %{
    code: 0x1a44,
    prefix: <<196, 52>>,
    name: "lamport-sha3-512-sig",
    description: "Lamport signature based on SHA3-512",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-512-sig"), do: get(0x1a44)
  
  def get(0x1a45), do: %{
    code: 0x1a45,
    prefix: <<197, 52>>,
    name: "lamport-sha3-384-sig",
    description: "Lamport signature based on SHA3-384",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-384-sig"), do: get(0x1a45)
  
  def get(0x1a46), do: %{
    code: 0x1a46,
    prefix: <<198, 52>>,
    name: "lamport-sha3-256-sig",
    description: "Lamport signature based on SHA3-256",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-256-sig"), do: get(0x1a46)
  
  def get(0x1a54), do: %{
    code: 0x1a54,
    prefix: <<212, 52>>,
    name: "lamport-sha3-512-sig-share",
    description: "Lamport signature share based on SHA3-512 and split with Shamir gf256",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-512-sig-share"), do: get(0x1a54)
  
  def get(0x1a55), do: %{
    code: 0x1a55,
    prefix: <<213, 52>>,
    name: "lamport-sha3-384-sig-share",
    description: "Lamport signature share based on SHA3-384 and split with Shamir gf256",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-384-sig-share"), do: get(0x1a55)
  
  def get(0x1a56), do: %{
    code: 0x1a56,
    prefix: <<214, 52>>,
    name: "lamport-sha3-256-sig-share",
    description: "Lamport signature share based on SHA3-256 and split with Shamir gf256",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-sha3-256-sig-share"), do: get(0x1a56)
  
  def get(0x1b), do: %{
    code: 0x1b,
    prefix: "\e",
    name: "keccak-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("keccak-256"), do: get(0x1b)
  
  def get(0x1c), do: %{
    code: 0x1c,
    prefix: <<28>>,
    name: "keccak-384",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("keccak-384"), do: get(0x1c)
  
  def get(0x1d), do: %{
    code: 0x1d,
    prefix: <<29>>,
    name: "keccak-512",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("keccak-512"), do: get(0x1d)
  
  def get(0x1d01), do: %{
    code: 0x1d01,
    prefix: <<129, 58>>,
    name: "kangarootwelve",
    description: "KangarooTwelve is an extendable-output hash function based on Keccak-p",
    status: "draft",
    tag: "multihash"
  }
  def get("kangarootwelve"), do: get(0x1d01)
  
  def get(0x1e), do: %{
    code: 0x1e,
    prefix: <<30>>,
    name: "blake3",
    description: "BLAKE3 has a default 32 byte output length. The maximum length is (2^64)-1 bytes.",
    status: "draft",
    tag: "multihash"
  }
  def get("blake3"), do: get(0x1e)
  
  def get(0x20), do: %{
    code: 0x20,
    prefix: " ",
    name: "sha2-384",
    description: "aka SHA-384; as specified by FIPS 180-4.",
    status: "permanent",
    tag: "multihash"
  }
  def get("sha2-384"), do: get(0x20)
  
  def get(0x2000), do: %{
    code: 0x2000,
    prefix: <<128, 64>>,
    name: "aes-gcm-256",
    description: "AES Galois/Counter Mode with 256-bit key and 12-byte IV",
    status: "draft",
    tag: "encryption"
  }
  def get("aes-gcm-256"), do: get(0x2000)
  
  def get(0x21), do: %{
    code: 0x21,
    prefix: "!",
    name: "dccp",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("dccp"), do: get(0x21)
  
  def get(0x22), do: %{
    code: 0x22,
    prefix: "\"",
    name: "murmur3-x64-64",
    description: "The first 64-bits of a murmur3-x64-128 - used for UnixFS directory sharding.",
    status: "permanent",
    tag: "hash"
  }
  def get("murmur3-x64-64"), do: get(0x22)
  
  def get(0x23), do: %{
    code: 0x23,
    prefix: "#",
    name: "murmur3-32",
    description: "",
    status: "draft",
    tag: "hash"
  }
  def get("murmur3-32"), do: get(0x23)
  
  def get(0x29), do: %{
    code: 0x29,
    prefix: ")",
    name: "ip6",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("ip6"), do: get(0x29)
  
  def get(0x2a), do: %{
    code: 0x2a,
    prefix: "*",
    name: "ip6zone",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("ip6zone"), do: get(0x2a)
  
  def get(0x2b), do: %{
    code: 0x2b,
    prefix: "+",
    name: "ipcidr",
    description: "CIDR mask for IP addresses",
    status: "draft",
    tag: "multiaddr"
  }
  def get("ipcidr"), do: get(0x2b)
  
  def get(0x2f), do: %{
    code: 0x2f,
    prefix: "/",
    name: "path",
    description: "Namespace for string paths. Corresponds to `/` in ASCII.",
    status: "permanent",
    tag: "namespace"
  }
  def get("path"), do: get(0x2f)
  
  def get(0x30), do: %{
    code: 0x30,
    prefix: "0",
    name: "multicodec",
    description: "",
    status: "draft",
    tag: "multiformat"
  }
  def get("multicodec"), do: get(0x30)
  
  def get(0x31), do: %{
    code: 0x31,
    prefix: "1",
    name: "multihash",
    description: "",
    status: "draft",
    tag: "multiformat"
  }
  def get("multihash"), do: get(0x31)
  
  def get(0x32), do: %{
    code: 0x32,
    prefix: "2",
    name: "multiaddr",
    description: "",
    status: "draft",
    tag: "multiformat"
  }
  def get("multiaddr"), do: get(0x32)
  
  def get(0x33), do: %{
    code: 0x33,
    prefix: "3",
    name: "multibase",
    description: "",
    status: "draft",
    tag: "multiformat"
  }
  def get("multibase"), do: get(0x33)
  
  def get(0x34), do: %{
    code: 0x34,
    prefix: "4",
    name: "varsig",
    description: "Variable signature (varsig) multiformat",
    status: "draft",
    tag: "multiformat"
  }
  def get("varsig"), do: get(0x34)
  
  def get(0x35), do: %{
    code: 0x35,
    prefix: "5",
    name: "dns",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("dns"), do: get(0x35)
  
  def get(0x36), do: %{
    code: 0x36,
    prefix: "6",
    name: "dns4",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("dns4"), do: get(0x36)
  
  def get(0x37), do: %{
    code: 0x37,
    prefix: "7",
    name: "dns6",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("dns6"), do: get(0x37)
  
  def get(0x38), do: %{
    code: 0x38,
    prefix: "8",
    name: "dnsaddr",
    description: "",
    status: "permanent",
    tag: "multiaddr"
  }
  def get("dnsaddr"), do: get(0x38)
  
  def get(0x3f42), do: %{
    code: 0x3f42,
    prefix: <<194, 126>>,
    name: "silverpine",
    description: "Experimental QUIC over yggdrasil and ironwood routing protocol",
    status: "draft",
    tag: "multiaddr"
  }
  def get("silverpine"), do: get(0x3f42)
  
  def get(0x50), do: %{
    code: 0x50,
    prefix: "P",
    name: "protobuf",
    description: "Protocol Buffers",
    status: "draft",
    tag: "serialization"
  }
  def get("protobuf"), do: get(0x50)
  
  def get(0x51), do: %{
    code: 0x51,
    prefix: "Q",
    name: "cbor",
    description: "CBOR",
    status: "permanent",
    tag: "ipld"
  }
  def get("cbor"), do: get(0x51)
  
  def get(0x511e00), do: %{
    code: 0x511e00,
    prefix: <<128, 188, 196, 2>>,
    name: "shelter-contract-manifest",
    description: "Shelter protocol contract manifest",
    status: "draft",
    tag: "shelter"
  }
  def get("shelter-contract-manifest"), do: get(0x511e00)
  
  def get(0x511e01), do: %{
    code: 0x511e01,
    prefix: <<129, 188, 196, 2>>,
    name: "shelter-contract-text",
    description: "Shelter protocol contract text",
    status: "draft",
    tag: "shelter"
  }
  def get("shelter-contract-text"), do: get(0x511e01)
  
  def get(0x511e02), do: %{
    code: 0x511e02,
    prefix: <<130, 188, 196, 2>>,
    name: "shelter-contract-data",
    description: "Shelter protocol contract data (contract chain)",
    status: "draft",
    tag: "shelter"
  }
  def get("shelter-contract-data"), do: get(0x511e02)
  
  def get(0x511e03), do: %{
    code: 0x511e03,
    prefix: <<131, 188, 196, 2>>,
    name: "shelter-file-manifest",
    description: "Shelter protocol file manifest",
    status: "draft",
    tag: "shelter"
  }
  def get("shelter-file-manifest"), do: get(0x511e03)
  
  def get(0x511e04), do: %{
    code: 0x511e04,
    prefix: <<132, 188, 196, 2>>,
    name: "shelter-file-chunk",
    description: "Shelter protocol file chunk",
    status: "draft",
    tag: "shelter"
  }
  def get("shelter-file-chunk"), do: get(0x511e04)
  
  def get(0x534d), do: %{
    code: 0x534d,
    prefix: <<205, 166, 1>>,
    name: "sm3-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("sm3-256"), do: get(0x534d)
  
  def get(0x55), do: %{
    code: 0x55,
    prefix: "U",
    name: "raw",
    description: "raw binary",
    status: "permanent",
    tag: "ipld"
  }
  def get("raw"), do: get(0x55)
  
  def get(0x56), do: %{
    code: 0x56,
    prefix: "V",
    name: "dbl-sha2-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("dbl-sha2-256"), do: get(0x56)
  
  def get(0x60), do: %{
    code: 0x60,
    prefix: "`",
    name: "rlp",
    description: "recursive length prefix",
    status: "draft",
    tag: "serialization"
  }
  def get("rlp"), do: get(0x60)
  
  def get(0x63), do: %{
    code: 0x63,
    prefix: "c",
    name: "bencode",
    description: "bencode",
    status: "draft",
    tag: "serialization"
  }
  def get("bencode"), do: get(0x63)
  
  def get(0x70), do: %{
    code: 0x70,
    prefix: "p",
    name: "dag-pb",
    description: "MerkleDAG protobuf",
    status: "permanent",
    tag: "ipld"
  }
  def get("dag-pb"), do: get(0x70)
  
  def get(0x7012), do: %{
    code: 0x7012,
    prefix: <<146, 224, 1>>,
    name: "sha256a",
    description: "The sum of multiple sha2-256 hashes; as specified by Ceramic CIP-124.",
    status: "draft",
    tag: "hash"
  }
  def get("sha256a"), do: get(0x7012)
  
  def get(0x706c61), do: %{
    code: 0x706c61,
    prefix: <<225, 216, 193, 3>>,
    name: "plaintextv2",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("plaintextv2"), do: get(0x706c61)
  
  def get(0x71), do: %{
    code: 0x71,
    prefix: "q",
    name: "dag-cbor",
    description: "MerkleDAG cbor",
    status: "permanent",
    tag: "ipld"
  }
  def get("dag-cbor"), do: get(0x71)
  
  def get(0x72), do: %{
    code: 0x72,
    prefix: "r",
    name: "libp2p-key",
    description: "Libp2p Public Key",
    status: "permanent",
    tag: "ipld"
  }
  def get("libp2p-key"), do: get(0x72)
  
  def get(0x78), do: %{
    code: 0x78,
    prefix: "x",
    name: "git-raw",
    description: "Raw Git object",
    status: "permanent",
    tag: "ipld"
  }
  def get("git-raw"), do: get(0x78)
  
  def get(0x7b), do: %{
    code: 0x7b,
    prefix: "{",
    name: "torrent-info",
    description: "Torrent file info field (bencoded)",
    status: "draft",
    tag: "ipld"
  }
  def get("torrent-info"), do: get(0x7b)
  
  def get(0x7c), do: %{
    code: 0x7c,
    prefix: "|",
    name: "torrent-file",
    description: "Torrent file (bencoded)",
    status: "draft",
    tag: "ipld"
  }
  def get("torrent-file"), do: get(0x7c)
  
  def get(0x80), do: %{
    code: 0x80,
    prefix: <<128, 1>>,
    name: "blake3-hashseq",
    description: "BLAKE3 hash sequence - per Iroh collections spec",
    status: "draft",
    tag: "ipld"
  }
  def get("blake3-hashseq"), do: get(0x80)
  
  def get(0x807124), do: %{
    code: 0x807124,
    prefix: <<164, 226, 129, 4>>,
    name: "holochain-adr-v0",
    description: "Holochain v0 address    + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-adr-v0"), do: get(0x807124)
  
  def get(0x81), do: %{
    code: 0x81,
    prefix: <<129, 1>>,
    name: "leofcoin-block",
    description: "Leofcoin Block",
    status: "draft",
    tag: "ipld"
  }
  def get("leofcoin-block"), do: get(0x81)
  
  def get(0x817124), do: %{
    code: 0x817124,
    prefix: <<164, 226, 133, 4>>,
    name: "holochain-adr-v1",
    description: "Holochain v1 address    + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-adr-v1"), do: get(0x817124)
  
  def get(0x82), do: %{
    code: 0x82,
    prefix: <<130, 1>>,
    name: "leofcoin-tx",
    description: "Leofcoin Transaction",
    status: "draft",
    tag: "ipld"
  }
  def get("leofcoin-tx"), do: get(0x82)
  
  def get(0x83), do: %{
    code: 0x83,
    prefix: <<131, 1>>,
    name: "leofcoin-pr",
    description: "Leofcoin Peer Reputation",
    status: "draft",
    tag: "ipld"
  }
  def get("leofcoin-pr"), do: get(0x83)
  
  def get(0x84), do: %{
    code: 0x84,
    prefix: <<132, 1>>,
    name: "sctp",
    description: "",
    status: "draft",
    tag: "multiaddr"
  }
  def get("sctp"), do: get(0x84)
  
  def get(0x85), do: %{
    code: 0x85,
    prefix: <<133, 1>>,
    name: "dag-jose",
    description: "MerkleDAG JOSE",
    status: "draft",
    tag: "ipld"
  }
  def get("dag-jose"), do: get(0x85)
  
  def get(0x86), do: %{
    code: 0x86,
    prefix: <<134, 1>>,
    name: "dag-cose",
    description: "MerkleDAG COSE",
    status: "draft",
    tag: "ipld"
  }
  def get("dag-cose"), do: get(0x86)
  
  def get(0x8c), do: %{
    code: 0x8c,
    prefix: <<140, 1>>,
    name: "lbry",
    description: "LBRY Address",
    status: "draft",
    tag: "namespace"
  }
  def get("lbry"), do: get(0x8c)
  
  def get(0x90), do: %{
    code: 0x90,
    prefix: <<144, 1>>,
    name: "eth-block",
    description: "Ethereum Header (RLP)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-block"), do: get(0x90)
  
  def get(0x91), do: %{
    code: 0x91,
    prefix: <<145, 1>>,
    name: "eth-block-list",
    description: "Ethereum Header List (RLP)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-block-list"), do: get(0x91)
  
  def get(0x92), do: %{
    code: 0x92,
    prefix: <<146, 1>>,
    name: "eth-tx-trie",
    description: "Ethereum Transaction Trie (Eth-Trie)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-tx-trie"), do: get(0x92)
  
  def get(0x93), do: %{
    code: 0x93,
    prefix: <<147, 1>>,
    name: "eth-tx",
    description: "Ethereum Transaction (MarshalBinary)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-tx"), do: get(0x93)
  
  def get(0x94), do: %{
    code: 0x94,
    prefix: <<148, 1>>,
    name: "eth-tx-receipt-trie",
    description: "Ethereum Transaction Receipt Trie (Eth-Trie)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-tx-receipt-trie"), do: get(0x94)
  
  def get(0x947124), do: %{
    code: 0x947124,
    prefix: <<164, 226, 209, 4>>,
    name: "holochain-key-v0",
    description: "Holochain v0 public key + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-key-v0"), do: get(0x947124)
  
  def get(0x95), do: %{
    code: 0x95,
    prefix: <<149, 1>>,
    name: "eth-tx-receipt",
    description: "Ethereum Transaction Receipt (MarshalBinary)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-tx-receipt"), do: get(0x95)
  
  def get(0x957124), do: %{
    code: 0x957124,
    prefix: <<164, 226, 213, 4>>,
    name: "holochain-key-v1",
    description: "Holochain v1 public key + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-key-v1"), do: get(0x957124)
  
  def get(0x96), do: %{
    code: 0x96,
    prefix: <<150, 1>>,
    name: "eth-state-trie",
    description: "Ethereum State Trie (Eth-Secure-Trie)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-state-trie"), do: get(0x96)
  
  def get(0x97), do: %{
    code: 0x97,
    prefix: <<151, 1>>,
    name: "eth-account-snapshot",
    description: "Ethereum Account Snapshot (RLP)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-account-snapshot"), do: get(0x97)
  
  def get(0x98), do: %{
    code: 0x98,
    prefix: <<152, 1>>,
    name: "eth-storage-trie",
    description: "Ethereum Contract Storage Trie (Eth-Secure-Trie)",
    status: "permanent",
    tag: "ipld"
  }
  def get("eth-storage-trie"), do: get(0x98)
  
  def get(0x99), do: %{
    code: 0x99,
    prefix: <<153, 1>>,
    name: "eth-receipt-log-trie",
    description: "Ethereum Transaction Receipt Log Trie (Eth-Trie)",
    status: "draft",
    tag: "ipld"
  }
  def get("eth-receipt-log-trie"), do: get(0x99)
  
  def get(0x9a), do: %{
    code: 0x9a,
    prefix: <<154, 1>>,
    name: "eth-receipt-log",
    description: "Ethereum Transaction Receipt Log (RLP)",
    status: "draft",
    tag: "ipld"
  }
  def get("eth-receipt-log"), do: get(0x9a)
  
  def get(0xa0), do: %{
    code: 0xa0,
    prefix: <<160, 1>>,
    name: "aes-128",
    description: "128-bit AES symmetric key",
    status: "draft",
    tag: "key"
  }
  def get("aes-128"), do: get(0xa0)
  
  def get(0xa000), do: %{
    code: 0xa000,
    prefix: <<128, 192, 2>>,
    name: "chacha20-poly1305",
    description: "ChaCha20_Poly1305 encryption scheme",
    status: "draft",
    tag: "multikey"
  }
  def get("chacha20-poly1305"), do: get(0xa000)
  
  def get(0xa1), do: %{
    code: 0xa1,
    prefix: <<161, 1>>,
    name: "aes-192",
    description: "192-bit AES symmetric key",
    status: "draft",
    tag: "key"
  }
  def get("aes-192"), do: get(0xa1)
  
  def get(0xa2), do: %{
    code: 0xa2,
    prefix: <<162, 1>>,
    name: "aes-256",
    description: "256-bit AES symmetric key",
    status: "draft",
    tag: "key"
  }
  def get("aes-256"), do: get(0xa2)
  
  def get(0xa27124), do: %{
    code: 0xa27124,
    prefix: <<164, 226, 137, 5>>,
    name: "holochain-sig-v0",
    description: "Holochain v0 signature  + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-sig-v0"), do: get(0xa27124)
  
  def get(0xa3), do: %{
    code: 0xa3,
    prefix: <<163, 1>>,
    name: "chacha-128",
    description: "128-bit ChaCha symmetric key",
    status: "draft",
    tag: "key"
  }
  def get("chacha-128"), do: get(0xa3)
  
  def get(0xa37124), do: %{
    code: 0xa37124,
    prefix: <<164, 226, 141, 5>>,
    name: "holochain-sig-v1",
    description: "Holochain v1 signature  + 8 R-S (63 x Base-32)",
    status: "draft",
    tag: "holochain"
  }
  def get("holochain-sig-v1"), do: get(0xa37124)
  
  def get(0xa4), do: %{
    code: 0xa4,
    prefix: <<164, 1>>,
    name: "chacha-256",
    description: "256-bit ChaCha symmetric key",
    status: "draft",
    tag: "key"
  }
  def get("chacha-256"), do: get(0xa4)
  
  def get(0xb0), do: %{
    code: 0xb0,
    prefix: <<176, 1>>,
    name: "bitcoin-block",
    description: "Bitcoin Block",
    status: "permanent",
    tag: "ipld"
  }
  def get("bitcoin-block"), do: get(0xb0)
  
  def get(0xb1), do: %{
    code: 0xb1,
    prefix: <<177, 1>>,
    name: "bitcoin-tx",
    description: "Bitcoin Tx",
    status: "permanent",
    tag: "ipld"
  }
  def get("bitcoin-tx"), do: get(0xb1)
  
  def get(0xb19910), do: %{
    code: 0xb19910,
    prefix: <<144, 178, 198, 5>>,
    name: "skynet-ns",
    description: "Skynet Namespace",
    status: "draft",
    tag: "namespace"
  }
  def get("skynet-ns"), do: get(0xb19910)
  
  def get(0xb2), do: %{
    code: 0xb2,
    prefix: <<178, 1>>,
    name: "bitcoin-witness-commitment",
    description: "Bitcoin Witness Commitment",
    status: "permanent",
    tag: "ipld"
  }
  def get("bitcoin-witness-commitment"), do: get(0xb2)
  
  def get(0xb201), do: %{
    code: 0xb201,
    prefix: <<129, 228, 2>>,
    name: "blake2b-8",
    description: "Blake2b consists of 64 output lengths that give different hashes",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-8"), do: get(0xb201)
  
  def get(0xb202), do: %{
    code: 0xb202,
    prefix: <<130, 228, 2>>,
    name: "blake2b-16",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-16"), do: get(0xb202)
  
  def get(0xb203), do: %{
    code: 0xb203,
    prefix: <<131, 228, 2>>,
    name: "blake2b-24",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-24"), do: get(0xb203)
  
  def get(0xb204), do: %{
    code: 0xb204,
    prefix: <<132, 228, 2>>,
    name: "blake2b-32",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-32"), do: get(0xb204)
  
  def get(0xb205), do: %{
    code: 0xb205,
    prefix: <<133, 228, 2>>,
    name: "blake2b-40",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-40"), do: get(0xb205)
  
  def get(0xb206), do: %{
    code: 0xb206,
    prefix: <<134, 228, 2>>,
    name: "blake2b-48",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-48"), do: get(0xb206)
  
  def get(0xb207), do: %{
    code: 0xb207,
    prefix: <<135, 228, 2>>,
    name: "blake2b-56",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-56"), do: get(0xb207)
  
  def get(0xb208), do: %{
    code: 0xb208,
    prefix: <<136, 228, 2>>,
    name: "blake2b-64",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-64"), do: get(0xb208)
  
  def get(0xb209), do: %{
    code: 0xb209,
    prefix: <<137, 228, 2>>,
    name: "blake2b-72",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-72"), do: get(0xb209)
  
  def get(0xb20a), do: %{
    code: 0xb20a,
    prefix: <<138, 228, 2>>,
    name: "blake2b-80",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-80"), do: get(0xb20a)
  
  def get(0xb20b), do: %{
    code: 0xb20b,
    prefix: <<139, 228, 2>>,
    name: "blake2b-88",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-88"), do: get(0xb20b)
  
  def get(0xb20c), do: %{
    code: 0xb20c,
    prefix: <<140, 228, 2>>,
    name: "blake2b-96",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-96"), do: get(0xb20c)
  
  def get(0xb20d), do: %{
    code: 0xb20d,
    prefix: <<141, 228, 2>>,
    name: "blake2b-104",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-104"), do: get(0xb20d)
  
  def get(0xb20e), do: %{
    code: 0xb20e,
    prefix: <<142, 228, 2>>,
    name: "blake2b-112",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-112"), do: get(0xb20e)
  
  def get(0xb20f), do: %{
    code: 0xb20f,
    prefix: <<143, 228, 2>>,
    name: "blake2b-120",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-120"), do: get(0xb20f)
  
  def get(0xb210), do: %{
    code: 0xb210,
    prefix: <<144, 228, 2>>,
    name: "blake2b-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-128"), do: get(0xb210)
  
  def get(0xb211), do: %{
    code: 0xb211,
    prefix: <<145, 228, 2>>,
    name: "blake2b-136",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-136"), do: get(0xb211)
  
  def get(0xb212), do: %{
    code: 0xb212,
    prefix: <<146, 228, 2>>,
    name: "blake2b-144",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-144"), do: get(0xb212)
  
  def get(0xb213), do: %{
    code: 0xb213,
    prefix: <<147, 228, 2>>,
    name: "blake2b-152",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-152"), do: get(0xb213)
  
  def get(0xb214), do: %{
    code: 0xb214,
    prefix: <<148, 228, 2>>,
    name: "blake2b-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-160"), do: get(0xb214)
  
  def get(0xb215), do: %{
    code: 0xb215,
    prefix: <<149, 228, 2>>,
    name: "blake2b-168",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-168"), do: get(0xb215)
  
  def get(0xb216), do: %{
    code: 0xb216,
    prefix: <<150, 228, 2>>,
    name: "blake2b-176",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-176"), do: get(0xb216)
  
  def get(0xb217), do: %{
    code: 0xb217,
    prefix: <<151, 228, 2>>,
    name: "blake2b-184",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-184"), do: get(0xb217)
  
  def get(0xb218), do: %{
    code: 0xb218,
    prefix: <<152, 228, 2>>,
    name: "blake2b-192",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-192"), do: get(0xb218)
  
  def get(0xb219), do: %{
    code: 0xb219,
    prefix: <<153, 228, 2>>,
    name: "blake2b-200",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-200"), do: get(0xb219)
  
  def get(0xb21a), do: %{
    code: 0xb21a,
    prefix: <<154, 228, 2>>,
    name: "blake2b-208",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-208"), do: get(0xb21a)
  
  def get(0xb21b), do: %{
    code: 0xb21b,
    prefix: <<155, 228, 2>>,
    name: "blake2b-216",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-216"), do: get(0xb21b)
  
  def get(0xb21c), do: %{
    code: 0xb21c,
    prefix: <<156, 228, 2>>,
    name: "blake2b-224",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-224"), do: get(0xb21c)
  
  def get(0xb21d), do: %{
    code: 0xb21d,
    prefix: <<157, 228, 2>>,
    name: "blake2b-232",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-232"), do: get(0xb21d)
  
  def get(0xb21e), do: %{
    code: 0xb21e,
    prefix: <<158, 228, 2>>,
    name: "blake2b-240",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-240"), do: get(0xb21e)
  
  def get(0xb21f), do: %{
    code: 0xb21f,
    prefix: <<159, 228, 2>>,
    name: "blake2b-248",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-248"), do: get(0xb21f)
  
  def get(0xb220), do: %{
    code: 0xb220,
    prefix: <<160, 228, 2>>,
    name: "blake2b-256",
    description: "",
    status: "permanent",
    tag: "multihash"
  }
  def get("blake2b-256"), do: get(0xb220)
  
  def get(0xb221), do: %{
    code: 0xb221,
    prefix: <<161, 228, 2>>,
    name: "blake2b-264",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-264"), do: get(0xb221)
  
  def get(0xb222), do: %{
    code: 0xb222,
    prefix: <<162, 228, 2>>,
    name: "blake2b-272",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-272"), do: get(0xb222)
  
  def get(0xb223), do: %{
    code: 0xb223,
    prefix: <<163, 228, 2>>,
    name: "blake2b-280",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-280"), do: get(0xb223)
  
  def get(0xb224), do: %{
    code: 0xb224,
    prefix: <<164, 228, 2>>,
    name: "blake2b-288",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-288"), do: get(0xb224)
  
  def get(0xb225), do: %{
    code: 0xb225,
    prefix: <<165, 228, 2>>,
    name: "blake2b-296",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-296"), do: get(0xb225)
  
  def get(0xb226), do: %{
    code: 0xb226,
    prefix: <<166, 228, 2>>,
    name: "blake2b-304",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-304"), do: get(0xb226)
  
  def get(0xb227), do: %{
    code: 0xb227,
    prefix: <<167, 228, 2>>,
    name: "blake2b-312",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-312"), do: get(0xb227)
  
  def get(0xb228), do: %{
    code: 0xb228,
    prefix: <<168, 228, 2>>,
    name: "blake2b-320",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-320"), do: get(0xb228)
  
  def get(0xb229), do: %{
    code: 0xb229,
    prefix: <<169, 228, 2>>,
    name: "blake2b-328",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-328"), do: get(0xb229)
  
  def get(0xb22a), do: %{
    code: 0xb22a,
    prefix: <<170, 228, 2>>,
    name: "blake2b-336",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-336"), do: get(0xb22a)
  
  def get(0xb22b), do: %{
    code: 0xb22b,
    prefix: <<171, 228, 2>>,
    name: "blake2b-344",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-344"), do: get(0xb22b)
  
  def get(0xb22c), do: %{
    code: 0xb22c,
    prefix: <<172, 228, 2>>,
    name: "blake2b-352",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-352"), do: get(0xb22c)
  
  def get(0xb22d), do: %{
    code: 0xb22d,
    prefix: <<173, 228, 2>>,
    name: "blake2b-360",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-360"), do: get(0xb22d)
  
  def get(0xb22e), do: %{
    code: 0xb22e,
    prefix: <<174, 228, 2>>,
    name: "blake2b-368",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-368"), do: get(0xb22e)
  
  def get(0xb22f), do: %{
    code: 0xb22f,
    prefix: <<175, 228, 2>>,
    name: "blake2b-376",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-376"), do: get(0xb22f)
  
  def get(0xb230), do: %{
    code: 0xb230,
    prefix: <<176, 228, 2>>,
    name: "blake2b-384",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-384"), do: get(0xb230)
  
  def get(0xb231), do: %{
    code: 0xb231,
    prefix: <<177, 228, 2>>,
    name: "blake2b-392",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-392"), do: get(0xb231)
  
  def get(0xb232), do: %{
    code: 0xb232,
    prefix: <<178, 228, 2>>,
    name: "blake2b-400",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-400"), do: get(0xb232)
  
  def get(0xb233), do: %{
    code: 0xb233,
    prefix: <<179, 228, 2>>,
    name: "blake2b-408",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-408"), do: get(0xb233)
  
  def get(0xb234), do: %{
    code: 0xb234,
    prefix: <<180, 228, 2>>,
    name: "blake2b-416",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-416"), do: get(0xb234)
  
  def get(0xb235), do: %{
    code: 0xb235,
    prefix: <<181, 228, 2>>,
    name: "blake2b-424",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-424"), do: get(0xb235)
  
  def get(0xb236), do: %{
    code: 0xb236,
    prefix: <<182, 228, 2>>,
    name: "blake2b-432",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-432"), do: get(0xb236)
  
  def get(0xb237), do: %{
    code: 0xb237,
    prefix: <<183, 228, 2>>,
    name: "blake2b-440",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-440"), do: get(0xb237)
  
  def get(0xb238), do: %{
    code: 0xb238,
    prefix: <<184, 228, 2>>,
    name: "blake2b-448",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-448"), do: get(0xb238)
  
  def get(0xb239), do: %{
    code: 0xb239,
    prefix: <<185, 228, 2>>,
    name: "blake2b-456",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-456"), do: get(0xb239)
  
  def get(0xb23a), do: %{
    code: 0xb23a,
    prefix: <<186, 228, 2>>,
    name: "blake2b-464",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-464"), do: get(0xb23a)
  
  def get(0xb23b), do: %{
    code: 0xb23b,
    prefix: <<187, 228, 2>>,
    name: "blake2b-472",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-472"), do: get(0xb23b)
  
  def get(0xb23c), do: %{
    code: 0xb23c,
    prefix: <<188, 228, 2>>,
    name: "blake2b-480",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-480"), do: get(0xb23c)
  
  def get(0xb23d), do: %{
    code: 0xb23d,
    prefix: <<189, 228, 2>>,
    name: "blake2b-488",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-488"), do: get(0xb23d)
  
  def get(0xb23e), do: %{
    code: 0xb23e,
    prefix: <<190, 228, 2>>,
    name: "blake2b-496",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-496"), do: get(0xb23e)
  
  def get(0xb23f), do: %{
    code: 0xb23f,
    prefix: <<191, 228, 2>>,
    name: "blake2b-504",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-504"), do: get(0xb23f)
  
  def get(0xb240), do: %{
    code: 0xb240,
    prefix: <<192, 228, 2>>,
    name: "blake2b-512",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2b-512"), do: get(0xb240)
  
  def get(0xb241), do: %{
    code: 0xb241,
    prefix: <<193, 228, 2>>,
    name: "blake2s-8",
    description: "Blake2s consists of 32 output lengths that give different hashes",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-8"), do: get(0xb241)
  
  def get(0xb242), do: %{
    code: 0xb242,
    prefix: <<194, 228, 2>>,
    name: "blake2s-16",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-16"), do: get(0xb242)
  
  def get(0xb243), do: %{
    code: 0xb243,
    prefix: <<195, 228, 2>>,
    name: "blake2s-24",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-24"), do: get(0xb243)
  
  def get(0xb244), do: %{
    code: 0xb244,
    prefix: <<196, 228, 2>>,
    name: "blake2s-32",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-32"), do: get(0xb244)
  
  def get(0xb245), do: %{
    code: 0xb245,
    prefix: <<197, 228, 2>>,
    name: "blake2s-40",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-40"), do: get(0xb245)
  
  def get(0xb246), do: %{
    code: 0xb246,
    prefix: <<198, 228, 2>>,
    name: "blake2s-48",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-48"), do: get(0xb246)
  
  def get(0xb247), do: %{
    code: 0xb247,
    prefix: <<199, 228, 2>>,
    name: "blake2s-56",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-56"), do: get(0xb247)
  
  def get(0xb248), do: %{
    code: 0xb248,
    prefix: <<200, 228, 2>>,
    name: "blake2s-64",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-64"), do: get(0xb248)
  
  def get(0xb249), do: %{
    code: 0xb249,
    prefix: <<201, 228, 2>>,
    name: "blake2s-72",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-72"), do: get(0xb249)
  
  def get(0xb24a), do: %{
    code: 0xb24a,
    prefix: <<202, 228, 2>>,
    name: "blake2s-80",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-80"), do: get(0xb24a)
  
  def get(0xb24b), do: %{
    code: 0xb24b,
    prefix: <<203, 228, 2>>,
    name: "blake2s-88",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-88"), do: get(0xb24b)
  
  def get(0xb24c), do: %{
    code: 0xb24c,
    prefix: <<204, 228, 2>>,
    name: "blake2s-96",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-96"), do: get(0xb24c)
  
  def get(0xb24d), do: %{
    code: 0xb24d,
    prefix: <<205, 228, 2>>,
    name: "blake2s-104",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-104"), do: get(0xb24d)
  
  def get(0xb24e), do: %{
    code: 0xb24e,
    prefix: <<206, 228, 2>>,
    name: "blake2s-112",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-112"), do: get(0xb24e)
  
  def get(0xb24f), do: %{
    code: 0xb24f,
    prefix: <<207, 228, 2>>,
    name: "blake2s-120",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-120"), do: get(0xb24f)
  
  def get(0xb250), do: %{
    code: 0xb250,
    prefix: <<208, 228, 2>>,
    name: "blake2s-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-128"), do: get(0xb250)
  
  def get(0xb251), do: %{
    code: 0xb251,
    prefix: <<209, 228, 2>>,
    name: "blake2s-136",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-136"), do: get(0xb251)
  
  def get(0xb252), do: %{
    code: 0xb252,
    prefix: <<210, 228, 2>>,
    name: "blake2s-144",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-144"), do: get(0xb252)
  
  def get(0xb253), do: %{
    code: 0xb253,
    prefix: <<211, 228, 2>>,
    name: "blake2s-152",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-152"), do: get(0xb253)
  
  def get(0xb254), do: %{
    code: 0xb254,
    prefix: <<212, 228, 2>>,
    name: "blake2s-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-160"), do: get(0xb254)
  
  def get(0xb255), do: %{
    code: 0xb255,
    prefix: <<213, 228, 2>>,
    name: "blake2s-168",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-168"), do: get(0xb255)
  
  def get(0xb256), do: %{
    code: 0xb256,
    prefix: <<214, 228, 2>>,
    name: "blake2s-176",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-176"), do: get(0xb256)
  
  def get(0xb257), do: %{
    code: 0xb257,
    prefix: <<215, 228, 2>>,
    name: "blake2s-184",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-184"), do: get(0xb257)
  
  def get(0xb258), do: %{
    code: 0xb258,
    prefix: <<216, 228, 2>>,
    name: "blake2s-192",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-192"), do: get(0xb258)
  
  def get(0xb259), do: %{
    code: 0xb259,
    prefix: <<217, 228, 2>>,
    name: "blake2s-200",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-200"), do: get(0xb259)
  
  def get(0xb25a), do: %{
    code: 0xb25a,
    prefix: <<218, 228, 2>>,
    name: "blake2s-208",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-208"), do: get(0xb25a)
  
  def get(0xb25b), do: %{
    code: 0xb25b,
    prefix: <<219, 228, 2>>,
    name: "blake2s-216",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-216"), do: get(0xb25b)
  
  def get(0xb25c), do: %{
    code: 0xb25c,
    prefix: <<220, 228, 2>>,
    name: "blake2s-224",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-224"), do: get(0xb25c)
  
  def get(0xb25d), do: %{
    code: 0xb25d,
    prefix: <<221, 228, 2>>,
    name: "blake2s-232",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-232"), do: get(0xb25d)
  
  def get(0xb25e), do: %{
    code: 0xb25e,
    prefix: <<222, 228, 2>>,
    name: "blake2s-240",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-240"), do: get(0xb25e)
  
  def get(0xb25f), do: %{
    code: 0xb25f,
    prefix: <<223, 228, 2>>,
    name: "blake2s-248",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-248"), do: get(0xb25f)
  
  def get(0xb260), do: %{
    code: 0xb260,
    prefix: <<224, 228, 2>>,
    name: "blake2s-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("blake2s-256"), do: get(0xb260)
  
  def get(0xb29910), do: %{
    code: 0xb29910,
    prefix: <<144, 178, 202, 5>>,
    name: "arweave-ns",
    description: "Arweave Namespace",
    status: "draft",
    tag: "namespace"
  }
  def get("arweave-ns"), do: get(0xb29910)
  
  def get(0xb301), do: %{
    code: 0xb301,
    prefix: <<129, 230, 2>>,
    name: "skein256-8",
    description: "Skein256 consists of 32 output lengths that give different hashes",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-8"), do: get(0xb301)
  
  def get(0xb302), do: %{
    code: 0xb302,
    prefix: <<130, 230, 2>>,
    name: "skein256-16",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-16"), do: get(0xb302)
  
  def get(0xb303), do: %{
    code: 0xb303,
    prefix: <<131, 230, 2>>,
    name: "skein256-24",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-24"), do: get(0xb303)
  
  def get(0xb304), do: %{
    code: 0xb304,
    prefix: <<132, 230, 2>>,
    name: "skein256-32",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-32"), do: get(0xb304)
  
  def get(0xb305), do: %{
    code: 0xb305,
    prefix: <<133, 230, 2>>,
    name: "skein256-40",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-40"), do: get(0xb305)
  
  def get(0xb306), do: %{
    code: 0xb306,
    prefix: <<134, 230, 2>>,
    name: "skein256-48",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-48"), do: get(0xb306)
  
  def get(0xb307), do: %{
    code: 0xb307,
    prefix: <<135, 230, 2>>,
    name: "skein256-56",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-56"), do: get(0xb307)
  
  def get(0xb308), do: %{
    code: 0xb308,
    prefix: <<136, 230, 2>>,
    name: "skein256-64",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-64"), do: get(0xb308)
  
  def get(0xb309), do: %{
    code: 0xb309,
    prefix: <<137, 230, 2>>,
    name: "skein256-72",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-72"), do: get(0xb309)
  
  def get(0xb30a), do: %{
    code: 0xb30a,
    prefix: <<138, 230, 2>>,
    name: "skein256-80",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-80"), do: get(0xb30a)
  
  def get(0xb30b), do: %{
    code: 0xb30b,
    prefix: <<139, 230, 2>>,
    name: "skein256-88",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-88"), do: get(0xb30b)
  
  def get(0xb30c), do: %{
    code: 0xb30c,
    prefix: <<140, 230, 2>>,
    name: "skein256-96",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-96"), do: get(0xb30c)
  
  def get(0xb30d), do: %{
    code: 0xb30d,
    prefix: <<141, 230, 2>>,
    name: "skein256-104",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-104"), do: get(0xb30d)
  
  def get(0xb30e), do: %{
    code: 0xb30e,
    prefix: <<142, 230, 2>>,
    name: "skein256-112",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-112"), do: get(0xb30e)
  
  def get(0xb30f), do: %{
    code: 0xb30f,
    prefix: <<143, 230, 2>>,
    name: "skein256-120",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-120"), do: get(0xb30f)
  
  def get(0xb310), do: %{
    code: 0xb310,
    prefix: <<144, 230, 2>>,
    name: "skein256-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-128"), do: get(0xb310)
  
  def get(0xb311), do: %{
    code: 0xb311,
    prefix: <<145, 230, 2>>,
    name: "skein256-136",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-136"), do: get(0xb311)
  
  def get(0xb312), do: %{
    code: 0xb312,
    prefix: <<146, 230, 2>>,
    name: "skein256-144",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-144"), do: get(0xb312)
  
  def get(0xb313), do: %{
    code: 0xb313,
    prefix: <<147, 230, 2>>,
    name: "skein256-152",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-152"), do: get(0xb313)
  
  def get(0xb314), do: %{
    code: 0xb314,
    prefix: <<148, 230, 2>>,
    name: "skein256-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-160"), do: get(0xb314)
  
  def get(0xb315), do: %{
    code: 0xb315,
    prefix: <<149, 230, 2>>,
    name: "skein256-168",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-168"), do: get(0xb315)
  
  def get(0xb316), do: %{
    code: 0xb316,
    prefix: <<150, 230, 2>>,
    name: "skein256-176",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-176"), do: get(0xb316)
  
  def get(0xb317), do: %{
    code: 0xb317,
    prefix: <<151, 230, 2>>,
    name: "skein256-184",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-184"), do: get(0xb317)
  
  def get(0xb318), do: %{
    code: 0xb318,
    prefix: <<152, 230, 2>>,
    name: "skein256-192",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-192"), do: get(0xb318)
  
  def get(0xb319), do: %{
    code: 0xb319,
    prefix: <<153, 230, 2>>,
    name: "skein256-200",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-200"), do: get(0xb319)
  
  def get(0xb31a), do: %{
    code: 0xb31a,
    prefix: <<154, 230, 2>>,
    name: "skein256-208",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-208"), do: get(0xb31a)
  
  def get(0xb31b), do: %{
    code: 0xb31b,
    prefix: <<155, 230, 2>>,
    name: "skein256-216",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-216"), do: get(0xb31b)
  
  def get(0xb31c), do: %{
    code: 0xb31c,
    prefix: <<156, 230, 2>>,
    name: "skein256-224",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-224"), do: get(0xb31c)
  
  def get(0xb31d), do: %{
    code: 0xb31d,
    prefix: <<157, 230, 2>>,
    name: "skein256-232",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-232"), do: get(0xb31d)
  
  def get(0xb31e), do: %{
    code: 0xb31e,
    prefix: <<158, 230, 2>>,
    name: "skein256-240",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-240"), do: get(0xb31e)
  
  def get(0xb31f), do: %{
    code: 0xb31f,
    prefix: <<159, 230, 2>>,
    name: "skein256-248",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-248"), do: get(0xb31f)
  
  def get(0xb320), do: %{
    code: 0xb320,
    prefix: <<160, 230, 2>>,
    name: "skein256-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein256-256"), do: get(0xb320)
  
  def get(0xb321), do: %{
    code: 0xb321,
    prefix: <<161, 230, 2>>,
    name: "skein512-8",
    description: "Skein512 consists of 64 output lengths that give different hashes",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-8"), do: get(0xb321)
  
  def get(0xb322), do: %{
    code: 0xb322,
    prefix: <<162, 230, 2>>,
    name: "skein512-16",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-16"), do: get(0xb322)
  
  def get(0xb323), do: %{
    code: 0xb323,
    prefix: <<163, 230, 2>>,
    name: "skein512-24",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-24"), do: get(0xb323)
  
  def get(0xb324), do: %{
    code: 0xb324,
    prefix: <<164, 230, 2>>,
    name: "skein512-32",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-32"), do: get(0xb324)
  
  def get(0xb325), do: %{
    code: 0xb325,
    prefix: <<165, 230, 2>>,
    name: "skein512-40",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-40"), do: get(0xb325)
  
  def get(0xb326), do: %{
    code: 0xb326,
    prefix: <<166, 230, 2>>,
    name: "skein512-48",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-48"), do: get(0xb326)
  
  def get(0xb327), do: %{
    code: 0xb327,
    prefix: <<167, 230, 2>>,
    name: "skein512-56",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-56"), do: get(0xb327)
  
  def get(0xb328), do: %{
    code: 0xb328,
    prefix: <<168, 230, 2>>,
    name: "skein512-64",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-64"), do: get(0xb328)
  
  def get(0xb329), do: %{
    code: 0xb329,
    prefix: <<169, 230, 2>>,
    name: "skein512-72",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-72"), do: get(0xb329)
  
  def get(0xb32a), do: %{
    code: 0xb32a,
    prefix: <<170, 230, 2>>,
    name: "skein512-80",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-80"), do: get(0xb32a)
  
  def get(0xb32b), do: %{
    code: 0xb32b,
    prefix: <<171, 230, 2>>,
    name: "skein512-88",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-88"), do: get(0xb32b)
  
  def get(0xb32c), do: %{
    code: 0xb32c,
    prefix: <<172, 230, 2>>,
    name: "skein512-96",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-96"), do: get(0xb32c)
  
  def get(0xb32d), do: %{
    code: 0xb32d,
    prefix: <<173, 230, 2>>,
    name: "skein512-104",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-104"), do: get(0xb32d)
  
  def get(0xb32e), do: %{
    code: 0xb32e,
    prefix: <<174, 230, 2>>,
    name: "skein512-112",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-112"), do: get(0xb32e)
  
  def get(0xb32f), do: %{
    code: 0xb32f,
    prefix: <<175, 230, 2>>,
    name: "skein512-120",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-120"), do: get(0xb32f)
  
  def get(0xb330), do: %{
    code: 0xb330,
    prefix: <<176, 230, 2>>,
    name: "skein512-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-128"), do: get(0xb330)
  
  def get(0xb331), do: %{
    code: 0xb331,
    prefix: <<177, 230, 2>>,
    name: "skein512-136",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-136"), do: get(0xb331)
  
  def get(0xb332), do: %{
    code: 0xb332,
    prefix: <<178, 230, 2>>,
    name: "skein512-144",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-144"), do: get(0xb332)
  
  def get(0xb333), do: %{
    code: 0xb333,
    prefix: <<179, 230, 2>>,
    name: "skein512-152",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-152"), do: get(0xb333)
  
  def get(0xb334), do: %{
    code: 0xb334,
    prefix: <<180, 230, 2>>,
    name: "skein512-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-160"), do: get(0xb334)
  
  def get(0xb335), do: %{
    code: 0xb335,
    prefix: <<181, 230, 2>>,
    name: "skein512-168",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-168"), do: get(0xb335)
  
  def get(0xb336), do: %{
    code: 0xb336,
    prefix: <<182, 230, 2>>,
    name: "skein512-176",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-176"), do: get(0xb336)
  
  def get(0xb337), do: %{
    code: 0xb337,
    prefix: <<183, 230, 2>>,
    name: "skein512-184",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-184"), do: get(0xb337)
  
  def get(0xb338), do: %{
    code: 0xb338,
    prefix: <<184, 230, 2>>,
    name: "skein512-192",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-192"), do: get(0xb338)
  
  def get(0xb339), do: %{
    code: 0xb339,
    prefix: <<185, 230, 2>>,
    name: "skein512-200",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-200"), do: get(0xb339)
  
  def get(0xb33a), do: %{
    code: 0xb33a,
    prefix: <<186, 230, 2>>,
    name: "skein512-208",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-208"), do: get(0xb33a)
  
  def get(0xb33b), do: %{
    code: 0xb33b,
    prefix: <<187, 230, 2>>,
    name: "skein512-216",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-216"), do: get(0xb33b)
  
  def get(0xb33c), do: %{
    code: 0xb33c,
    prefix: <<188, 230, 2>>,
    name: "skein512-224",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-224"), do: get(0xb33c)
  
  def get(0xb33d), do: %{
    code: 0xb33d,
    prefix: <<189, 230, 2>>,
    name: "skein512-232",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-232"), do: get(0xb33d)
  
  def get(0xb33e), do: %{
    code: 0xb33e,
    prefix: <<190, 230, 2>>,
    name: "skein512-240",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-240"), do: get(0xb33e)
  
  def get(0xb33f), do: %{
    code: 0xb33f,
    prefix: <<191, 230, 2>>,
    name: "skein512-248",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-248"), do: get(0xb33f)
  
  def get(0xb340), do: %{
    code: 0xb340,
    prefix: <<192, 230, 2>>,
    name: "skein512-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-256"), do: get(0xb340)
  
  def get(0xb341), do: %{
    code: 0xb341,
    prefix: <<193, 230, 2>>,
    name: "skein512-264",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-264"), do: get(0xb341)
  
  def get(0xb342), do: %{
    code: 0xb342,
    prefix: <<194, 230, 2>>,
    name: "skein512-272",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-272"), do: get(0xb342)
  
  def get(0xb343), do: %{
    code: 0xb343,
    prefix: <<195, 230, 2>>,
    name: "skein512-280",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-280"), do: get(0xb343)
  
  def get(0xb344), do: %{
    code: 0xb344,
    prefix: <<196, 230, 2>>,
    name: "skein512-288",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-288"), do: get(0xb344)
  
  def get(0xb345), do: %{
    code: 0xb345,
    prefix: <<197, 230, 2>>,
    name: "skein512-296",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-296"), do: get(0xb345)
  
  def get(0xb346), do: %{
    code: 0xb346,
    prefix: <<198, 230, 2>>,
    name: "skein512-304",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-304"), do: get(0xb346)
  
  def get(0xb347), do: %{
    code: 0xb347,
    prefix: <<199, 230, 2>>,
    name: "skein512-312",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-312"), do: get(0xb347)
  
  def get(0xb348), do: %{
    code: 0xb348,
    prefix: <<200, 230, 2>>,
    name: "skein512-320",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-320"), do: get(0xb348)
  
  def get(0xb349), do: %{
    code: 0xb349,
    prefix: <<201, 230, 2>>,
    name: "skein512-328",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-328"), do: get(0xb349)
  
  def get(0xb34a), do: %{
    code: 0xb34a,
    prefix: <<202, 230, 2>>,
    name: "skein512-336",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-336"), do: get(0xb34a)
  
  def get(0xb34b), do: %{
    code: 0xb34b,
    prefix: <<203, 230, 2>>,
    name: "skein512-344",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-344"), do: get(0xb34b)
  
  def get(0xb34c), do: %{
    code: 0xb34c,
    prefix: <<204, 230, 2>>,
    name: "skein512-352",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-352"), do: get(0xb34c)
  
  def get(0xb34d), do: %{
    code: 0xb34d,
    prefix: <<205, 230, 2>>,
    name: "skein512-360",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-360"), do: get(0xb34d)
  
  def get(0xb34e), do: %{
    code: 0xb34e,
    prefix: <<206, 230, 2>>,
    name: "skein512-368",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-368"), do: get(0xb34e)
  
  def get(0xb34f), do: %{
    code: 0xb34f,
    prefix: <<207, 230, 2>>,
    name: "skein512-376",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-376"), do: get(0xb34f)
  
  def get(0xb350), do: %{
    code: 0xb350,
    prefix: <<208, 230, 2>>,
    name: "skein512-384",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-384"), do: get(0xb350)
  
  def get(0xb351), do: %{
    code: 0xb351,
    prefix: <<209, 230, 2>>,
    name: "skein512-392",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-392"), do: get(0xb351)
  
  def get(0xb352), do: %{
    code: 0xb352,
    prefix: <<210, 230, 2>>,
    name: "skein512-400",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-400"), do: get(0xb352)
  
  def get(0xb353), do: %{
    code: 0xb353,
    prefix: <<211, 230, 2>>,
    name: "skein512-408",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-408"), do: get(0xb353)
  
  def get(0xb354), do: %{
    code: 0xb354,
    prefix: <<212, 230, 2>>,
    name: "skein512-416",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-416"), do: get(0xb354)
  
  def get(0xb355), do: %{
    code: 0xb355,
    prefix: <<213, 230, 2>>,
    name: "skein512-424",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-424"), do: get(0xb355)
  
  def get(0xb356), do: %{
    code: 0xb356,
    prefix: <<214, 230, 2>>,
    name: "skein512-432",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-432"), do: get(0xb356)
  
  def get(0xb357), do: %{
    code: 0xb357,
    prefix: <<215, 230, 2>>,
    name: "skein512-440",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-440"), do: get(0xb357)
  
  def get(0xb358), do: %{
    code: 0xb358,
    prefix: <<216, 230, 2>>,
    name: "skein512-448",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-448"), do: get(0xb358)
  
  def get(0xb359), do: %{
    code: 0xb359,
    prefix: <<217, 230, 2>>,
    name: "skein512-456",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-456"), do: get(0xb359)
  
  def get(0xb35a), do: %{
    code: 0xb35a,
    prefix: <<218, 230, 2>>,
    name: "skein512-464",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-464"), do: get(0xb35a)
  
  def get(0xb35b), do: %{
    code: 0xb35b,
    prefix: <<219, 230, 2>>,
    name: "skein512-472",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-472"), do: get(0xb35b)
  
  def get(0xb35c), do: %{
    code: 0xb35c,
    prefix: <<220, 230, 2>>,
    name: "skein512-480",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-480"), do: get(0xb35c)
  
  def get(0xb35d), do: %{
    code: 0xb35d,
    prefix: <<221, 230, 2>>,
    name: "skein512-488",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-488"), do: get(0xb35d)
  
  def get(0xb35e), do: %{
    code: 0xb35e,
    prefix: <<222, 230, 2>>,
    name: "skein512-496",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-496"), do: get(0xb35e)
  
  def get(0xb35f), do: %{
    code: 0xb35f,
    prefix: <<223, 230, 2>>,
    name: "skein512-504",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-504"), do: get(0xb35f)
  
  def get(0xb360), do: %{
    code: 0xb360,
    prefix: <<224, 230, 2>>,
    name: "skein512-512",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein512-512"), do: get(0xb360)
  
  def get(0xb361), do: %{
    code: 0xb361,
    prefix: <<225, 230, 2>>,
    name: "skein1024-8",
    description: "Skein1024 consists of 128 output lengths that give different hashes",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-8"), do: get(0xb361)
  
  def get(0xb362), do: %{
    code: 0xb362,
    prefix: <<226, 230, 2>>,
    name: "skein1024-16",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-16"), do: get(0xb362)
  
  def get(0xb363), do: %{
    code: 0xb363,
    prefix: <<227, 230, 2>>,
    name: "skein1024-24",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-24"), do: get(0xb363)
  
  def get(0xb364), do: %{
    code: 0xb364,
    prefix: <<228, 230, 2>>,
    name: "skein1024-32",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-32"), do: get(0xb364)
  
  def get(0xb365), do: %{
    code: 0xb365,
    prefix: <<229, 230, 2>>,
    name: "skein1024-40",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-40"), do: get(0xb365)
  
  def get(0xb366), do: %{
    code: 0xb366,
    prefix: <<230, 230, 2>>,
    name: "skein1024-48",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-48"), do: get(0xb366)
  
  def get(0xb367), do: %{
    code: 0xb367,
    prefix: <<231, 230, 2>>,
    name: "skein1024-56",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-56"), do: get(0xb367)
  
  def get(0xb368), do: %{
    code: 0xb368,
    prefix: <<232, 230, 2>>,
    name: "skein1024-64",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-64"), do: get(0xb368)
  
  def get(0xb369), do: %{
    code: 0xb369,
    prefix: <<233, 230, 2>>,
    name: "skein1024-72",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-72"), do: get(0xb369)
  
  def get(0xb36a), do: %{
    code: 0xb36a,
    prefix: <<234, 230, 2>>,
    name: "skein1024-80",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-80"), do: get(0xb36a)
  
  def get(0xb36b), do: %{
    code: 0xb36b,
    prefix: <<235, 230, 2>>,
    name: "skein1024-88",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-88"), do: get(0xb36b)
  
  def get(0xb36c), do: %{
    code: 0xb36c,
    prefix: <<236, 230, 2>>,
    name: "skein1024-96",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-96"), do: get(0xb36c)
  
  def get(0xb36d), do: %{
    code: 0xb36d,
    prefix: <<237, 230, 2>>,
    name: "skein1024-104",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-104"), do: get(0xb36d)
  
  def get(0xb36e), do: %{
    code: 0xb36e,
    prefix: <<238, 230, 2>>,
    name: "skein1024-112",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-112"), do: get(0xb36e)
  
  def get(0xb36f), do: %{
    code: 0xb36f,
    prefix: <<239, 230, 2>>,
    name: "skein1024-120",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-120"), do: get(0xb36f)
  
  def get(0xb370), do: %{
    code: 0xb370,
    prefix: <<240, 230, 2>>,
    name: "skein1024-128",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-128"), do: get(0xb370)
  
  def get(0xb371), do: %{
    code: 0xb371,
    prefix: <<241, 230, 2>>,
    name: "skein1024-136",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-136"), do: get(0xb371)
  
  def get(0xb372), do: %{
    code: 0xb372,
    prefix: <<242, 230, 2>>,
    name: "skein1024-144",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-144"), do: get(0xb372)
  
  def get(0xb373), do: %{
    code: 0xb373,
    prefix: <<243, 230, 2>>,
    name: "skein1024-152",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-152"), do: get(0xb373)
  
  def get(0xb374), do: %{
    code: 0xb374,
    prefix: <<244, 230, 2>>,
    name: "skein1024-160",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-160"), do: get(0xb374)
  
  def get(0xb375), do: %{
    code: 0xb375,
    prefix: <<245, 230, 2>>,
    name: "skein1024-168",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-168"), do: get(0xb375)
  
  def get(0xb376), do: %{
    code: 0xb376,
    prefix: <<246, 230, 2>>,
    name: "skein1024-176",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-176"), do: get(0xb376)
  
  def get(0xb377), do: %{
    code: 0xb377,
    prefix: <<247, 230, 2>>,
    name: "skein1024-184",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-184"), do: get(0xb377)
  
  def get(0xb378), do: %{
    code: 0xb378,
    prefix: <<248, 230, 2>>,
    name: "skein1024-192",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-192"), do: get(0xb378)
  
  def get(0xb379), do: %{
    code: 0xb379,
    prefix: <<249, 230, 2>>,
    name: "skein1024-200",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-200"), do: get(0xb379)
  
  def get(0xb37a), do: %{
    code: 0xb37a,
    prefix: <<250, 230, 2>>,
    name: "skein1024-208",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-208"), do: get(0xb37a)
  
  def get(0xb37b), do: %{
    code: 0xb37b,
    prefix: <<251, 230, 2>>,
    name: "skein1024-216",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-216"), do: get(0xb37b)
  
  def get(0xb37c), do: %{
    code: 0xb37c,
    prefix: <<252, 230, 2>>,
    name: "skein1024-224",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-224"), do: get(0xb37c)
  
  def get(0xb37d), do: %{
    code: 0xb37d,
    prefix: <<253, 230, 2>>,
    name: "skein1024-232",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-232"), do: get(0xb37d)
  
  def get(0xb37e), do: %{
    code: 0xb37e,
    prefix: <<254, 230, 2>>,
    name: "skein1024-240",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-240"), do: get(0xb37e)
  
  def get(0xb37f), do: %{
    code: 0xb37f,
    prefix: <<255, 230, 2>>,
    name: "skein1024-248",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-248"), do: get(0xb37f)
  
  def get(0xb380), do: %{
    code: 0xb380,
    prefix: <<128, 231, 2>>,
    name: "skein1024-256",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-256"), do: get(0xb380)
  
  def get(0xb381), do: %{
    code: 0xb381,
    prefix: <<129, 231, 2>>,
    name: "skein1024-264",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-264"), do: get(0xb381)
  
  def get(0xb382), do: %{
    code: 0xb382,
    prefix: <<130, 231, 2>>,
    name: "skein1024-272",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-272"), do: get(0xb382)
  
  def get(0xb383), do: %{
    code: 0xb383,
    prefix: <<131, 231, 2>>,
    name: "skein1024-280",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-280"), do: get(0xb383)
  
  def get(0xb384), do: %{
    code: 0xb384,
    prefix: <<132, 231, 2>>,
    name: "skein1024-288",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-288"), do: get(0xb384)
  
  def get(0xb385), do: %{
    code: 0xb385,
    prefix: <<133, 231, 2>>,
    name: "skein1024-296",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-296"), do: get(0xb385)
  
  def get(0xb386), do: %{
    code: 0xb386,
    prefix: <<134, 231, 2>>,
    name: "skein1024-304",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-304"), do: get(0xb386)
  
  def get(0xb387), do: %{
    code: 0xb387,
    prefix: <<135, 231, 2>>,
    name: "skein1024-312",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-312"), do: get(0xb387)
  
  def get(0xb388), do: %{
    code: 0xb388,
    prefix: <<136, 231, 2>>,
    name: "skein1024-320",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-320"), do: get(0xb388)
  
  def get(0xb389), do: %{
    code: 0xb389,
    prefix: <<137, 231, 2>>,
    name: "skein1024-328",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-328"), do: get(0xb389)
  
  def get(0xb38a), do: %{
    code: 0xb38a,
    prefix: <<138, 231, 2>>,
    name: "skein1024-336",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-336"), do: get(0xb38a)
  
  def get(0xb38b), do: %{
    code: 0xb38b,
    prefix: <<139, 231, 2>>,
    name: "skein1024-344",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-344"), do: get(0xb38b)
  
  def get(0xb38c), do: %{
    code: 0xb38c,
    prefix: <<140, 231, 2>>,
    name: "skein1024-352",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-352"), do: get(0xb38c)
  
  def get(0xb38d), do: %{
    code: 0xb38d,
    prefix: <<141, 231, 2>>,
    name: "skein1024-360",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-360"), do: get(0xb38d)
  
  def get(0xb38e), do: %{
    code: 0xb38e,
    prefix: <<142, 231, 2>>,
    name: "skein1024-368",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-368"), do: get(0xb38e)
  
  def get(0xb38f), do: %{
    code: 0xb38f,
    prefix: <<143, 231, 2>>,
    name: "skein1024-376",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-376"), do: get(0xb38f)
  
  def get(0xb390), do: %{
    code: 0xb390,
    prefix: <<144, 231, 2>>,
    name: "skein1024-384",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-384"), do: get(0xb390)
  
  def get(0xb391), do: %{
    code: 0xb391,
    prefix: <<145, 231, 2>>,
    name: "skein1024-392",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-392"), do: get(0xb391)
  
  def get(0xb392), do: %{
    code: 0xb392,
    prefix: <<146, 231, 2>>,
    name: "skein1024-400",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-400"), do: get(0xb392)
  
  def get(0xb393), do: %{
    code: 0xb393,
    prefix: <<147, 231, 2>>,
    name: "skein1024-408",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-408"), do: get(0xb393)
  
  def get(0xb394), do: %{
    code: 0xb394,
    prefix: <<148, 231, 2>>,
    name: "skein1024-416",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-416"), do: get(0xb394)
  
  def get(0xb395), do: %{
    code: 0xb395,
    prefix: <<149, 231, 2>>,
    name: "skein1024-424",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-424"), do: get(0xb395)
  
  def get(0xb396), do: %{
    code: 0xb396,
    prefix: <<150, 231, 2>>,
    name: "skein1024-432",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-432"), do: get(0xb396)
  
  def get(0xb397), do: %{
    code: 0xb397,
    prefix: <<151, 231, 2>>,
    name: "skein1024-440",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-440"), do: get(0xb397)
  
  def get(0xb398), do: %{
    code: 0xb398,
    prefix: <<152, 231, 2>>,
    name: "skein1024-448",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-448"), do: get(0xb398)
  
  def get(0xb399), do: %{
    code: 0xb399,
    prefix: <<153, 231, 2>>,
    name: "skein1024-456",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-456"), do: get(0xb399)
  
  def get(0xb39910), do: %{
    code: 0xb39910,
    prefix: <<144, 178, 206, 5>>,
    name: "subspace-ns",
    description: "Subspace Network Namespace",
    status: "draft",
    tag: "namespace"
  }
  def get("subspace-ns"), do: get(0xb39910)
  
  def get(0xb39a), do: %{
    code: 0xb39a,
    prefix: <<154, 231, 2>>,
    name: "skein1024-464",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-464"), do: get(0xb39a)
  
  def get(0xb39b), do: %{
    code: 0xb39b,
    prefix: <<155, 231, 2>>,
    name: "skein1024-472",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-472"), do: get(0xb39b)
  
  def get(0xb39c), do: %{
    code: 0xb39c,
    prefix: <<156, 231, 2>>,
    name: "skein1024-480",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-480"), do: get(0xb39c)
  
  def get(0xb39d), do: %{
    code: 0xb39d,
    prefix: <<157, 231, 2>>,
    name: "skein1024-488",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-488"), do: get(0xb39d)
  
  def get(0xb39e), do: %{
    code: 0xb39e,
    prefix: <<158, 231, 2>>,
    name: "skein1024-496",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-496"), do: get(0xb39e)
  
  def get(0xb39f), do: %{
    code: 0xb39f,
    prefix: <<159, 231, 2>>,
    name: "skein1024-504",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-504"), do: get(0xb39f)
  
  def get(0xb3a0), do: %{
    code: 0xb3a0,
    prefix: <<160, 231, 2>>,
    name: "skein1024-512",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-512"), do: get(0xb3a0)
  
  def get(0xb3a1), do: %{
    code: 0xb3a1,
    prefix: <<161, 231, 2>>,
    name: "skein1024-520",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-520"), do: get(0xb3a1)
  
  def get(0xb3a2), do: %{
    code: 0xb3a2,
    prefix: <<162, 231, 2>>,
    name: "skein1024-528",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-528"), do: get(0xb3a2)
  
  def get(0xb3a3), do: %{
    code: 0xb3a3,
    prefix: <<163, 231, 2>>,
    name: "skein1024-536",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-536"), do: get(0xb3a3)
  
  def get(0xb3a4), do: %{
    code: 0xb3a4,
    prefix: <<164, 231, 2>>,
    name: "skein1024-544",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-544"), do: get(0xb3a4)
  
  def get(0xb3a5), do: %{
    code: 0xb3a5,
    prefix: <<165, 231, 2>>,
    name: "skein1024-552",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-552"), do: get(0xb3a5)
  
  def get(0xb3a6), do: %{
    code: 0xb3a6,
    prefix: <<166, 231, 2>>,
    name: "skein1024-560",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-560"), do: get(0xb3a6)
  
  def get(0xb3a7), do: %{
    code: 0xb3a7,
    prefix: <<167, 231, 2>>,
    name: "skein1024-568",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-568"), do: get(0xb3a7)
  
  def get(0xb3a8), do: %{
    code: 0xb3a8,
    prefix: <<168, 231, 2>>,
    name: "skein1024-576",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-576"), do: get(0xb3a8)
  
  def get(0xb3a9), do: %{
    code: 0xb3a9,
    prefix: <<169, 231, 2>>,
    name: "skein1024-584",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-584"), do: get(0xb3a9)
  
  def get(0xb3aa), do: %{
    code: 0xb3aa,
    prefix: <<170, 231, 2>>,
    name: "skein1024-592",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-592"), do: get(0xb3aa)
  
  def get(0xb3ab), do: %{
    code: 0xb3ab,
    prefix: <<171, 231, 2>>,
    name: "skein1024-600",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-600"), do: get(0xb3ab)
  
  def get(0xb3ac), do: %{
    code: 0xb3ac,
    prefix: <<172, 231, 2>>,
    name: "skein1024-608",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-608"), do: get(0xb3ac)
  
  def get(0xb3ad), do: %{
    code: 0xb3ad,
    prefix: <<173, 231, 2>>,
    name: "skein1024-616",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-616"), do: get(0xb3ad)
  
  def get(0xb3ae), do: %{
    code: 0xb3ae,
    prefix: <<174, 231, 2>>,
    name: "skein1024-624",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-624"), do: get(0xb3ae)
  
  def get(0xb3af), do: %{
    code: 0xb3af,
    prefix: <<175, 231, 2>>,
    name: "skein1024-632",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-632"), do: get(0xb3af)
  
  def get(0xb3b0), do: %{
    code: 0xb3b0,
    prefix: <<176, 231, 2>>,
    name: "skein1024-640",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-640"), do: get(0xb3b0)
  
  def get(0xb3b1), do: %{
    code: 0xb3b1,
    prefix: <<177, 231, 2>>,
    name: "skein1024-648",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-648"), do: get(0xb3b1)
  
  def get(0xb3b2), do: %{
    code: 0xb3b2,
    prefix: <<178, 231, 2>>,
    name: "skein1024-656",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-656"), do: get(0xb3b2)
  
  def get(0xb3b3), do: %{
    code: 0xb3b3,
    prefix: <<179, 231, 2>>,
    name: "skein1024-664",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-664"), do: get(0xb3b3)
  
  def get(0xb3b4), do: %{
    code: 0xb3b4,
    prefix: <<180, 231, 2>>,
    name: "skein1024-672",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-672"), do: get(0xb3b4)
  
  def get(0xb3b5), do: %{
    code: 0xb3b5,
    prefix: <<181, 231, 2>>,
    name: "skein1024-680",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-680"), do: get(0xb3b5)
  
  def get(0xb3b6), do: %{
    code: 0xb3b6,
    prefix: <<182, 231, 2>>,
    name: "skein1024-688",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-688"), do: get(0xb3b6)
  
  def get(0xb3b7), do: %{
    code: 0xb3b7,
    prefix: <<183, 231, 2>>,
    name: "skein1024-696",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-696"), do: get(0xb3b7)
  
  def get(0xb3b8), do: %{
    code: 0xb3b8,
    prefix: <<184, 231, 2>>,
    name: "skein1024-704",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-704"), do: get(0xb3b8)
  
  def get(0xb3b9), do: %{
    code: 0xb3b9,
    prefix: <<185, 231, 2>>,
    name: "skein1024-712",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-712"), do: get(0xb3b9)
  
  def get(0xb3ba), do: %{
    code: 0xb3ba,
    prefix: <<186, 231, 2>>,
    name: "skein1024-720",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-720"), do: get(0xb3ba)
  
  def get(0xb3bb), do: %{
    code: 0xb3bb,
    prefix: <<187, 231, 2>>,
    name: "skein1024-728",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-728"), do: get(0xb3bb)
  
  def get(0xb3bc), do: %{
    code: 0xb3bc,
    prefix: <<188, 231, 2>>,
    name: "skein1024-736",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-736"), do: get(0xb3bc)
  
  def get(0xb3bd), do: %{
    code: 0xb3bd,
    prefix: <<189, 231, 2>>,
    name: "skein1024-744",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-744"), do: get(0xb3bd)
  
  def get(0xb3be), do: %{
    code: 0xb3be,
    prefix: <<190, 231, 2>>,
    name: "skein1024-752",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-752"), do: get(0xb3be)
  
  def get(0xb3bf), do: %{
    code: 0xb3bf,
    prefix: <<191, 231, 2>>,
    name: "skein1024-760",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-760"), do: get(0xb3bf)
  
  def get(0xb3c0), do: %{
    code: 0xb3c0,
    prefix: <<192, 231, 2>>,
    name: "skein1024-768",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-768"), do: get(0xb3c0)
  
  def get(0xb3c1), do: %{
    code: 0xb3c1,
    prefix: <<193, 231, 2>>,
    name: "skein1024-776",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-776"), do: get(0xb3c1)
  
  def get(0xb3c2), do: %{
    code: 0xb3c2,
    prefix: <<194, 231, 2>>,
    name: "skein1024-784",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-784"), do: get(0xb3c2)
  
  def get(0xb3c3), do: %{
    code: 0xb3c3,
    prefix: <<195, 231, 2>>,
    name: "skein1024-792",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-792"), do: get(0xb3c3)
  
  def get(0xb3c4), do: %{
    code: 0xb3c4,
    prefix: <<196, 231, 2>>,
    name: "skein1024-800",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-800"), do: get(0xb3c4)
  
  def get(0xb3c5), do: %{
    code: 0xb3c5,
    prefix: <<197, 231, 2>>,
    name: "skein1024-808",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-808"), do: get(0xb3c5)
  
  def get(0xb3c6), do: %{
    code: 0xb3c6,
    prefix: <<198, 231, 2>>,
    name: "skein1024-816",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-816"), do: get(0xb3c6)
  
  def get(0xb3c7), do: %{
    code: 0xb3c7,
    prefix: <<199, 231, 2>>,
    name: "skein1024-824",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-824"), do: get(0xb3c7)
  
  def get(0xb3c8), do: %{
    code: 0xb3c8,
    prefix: <<200, 231, 2>>,
    name: "skein1024-832",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-832"), do: get(0xb3c8)
  
  def get(0xb3c9), do: %{
    code: 0xb3c9,
    prefix: <<201, 231, 2>>,
    name: "skein1024-840",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-840"), do: get(0xb3c9)
  
  def get(0xb3ca), do: %{
    code: 0xb3ca,
    prefix: <<202, 231, 2>>,
    name: "skein1024-848",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-848"), do: get(0xb3ca)
  
  def get(0xb3cb), do: %{
    code: 0xb3cb,
    prefix: <<203, 231, 2>>,
    name: "skein1024-856",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-856"), do: get(0xb3cb)
  
  def get(0xb3cc), do: %{
    code: 0xb3cc,
    prefix: <<204, 231, 2>>,
    name: "skein1024-864",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-864"), do: get(0xb3cc)
  
  def get(0xb3cd), do: %{
    code: 0xb3cd,
    prefix: <<205, 231, 2>>,
    name: "skein1024-872",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-872"), do: get(0xb3cd)
  
  def get(0xb3ce), do: %{
    code: 0xb3ce,
    prefix: <<206, 231, 2>>,
    name: "skein1024-880",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-880"), do: get(0xb3ce)
  
  def get(0xb3cf), do: %{
    code: 0xb3cf,
    prefix: <<207, 231, 2>>,
    name: "skein1024-888",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-888"), do: get(0xb3cf)
  
  def get(0xb3d0), do: %{
    code: 0xb3d0,
    prefix: <<208, 231, 2>>,
    name: "skein1024-896",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-896"), do: get(0xb3d0)
  
  def get(0xb3d1), do: %{
    code: 0xb3d1,
    prefix: <<209, 231, 2>>,
    name: "skein1024-904",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-904"), do: get(0xb3d1)
  
  def get(0xb3d2), do: %{
    code: 0xb3d2,
    prefix: <<210, 231, 2>>,
    name: "skein1024-912",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-912"), do: get(0xb3d2)
  
  def get(0xb3d3), do: %{
    code: 0xb3d3,
    prefix: <<211, 231, 2>>,
    name: "skein1024-920",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-920"), do: get(0xb3d3)
  
  def get(0xb3d4), do: %{
    code: 0xb3d4,
    prefix: <<212, 231, 2>>,
    name: "skein1024-928",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-928"), do: get(0xb3d4)
  
  def get(0xb3d5), do: %{
    code: 0xb3d5,
    prefix: <<213, 231, 2>>,
    name: "skein1024-936",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-936"), do: get(0xb3d5)
  
  def get(0xb3d6), do: %{
    code: 0xb3d6,
    prefix: <<214, 231, 2>>,
    name: "skein1024-944",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-944"), do: get(0xb3d6)
  
  def get(0xb3d7), do: %{
    code: 0xb3d7,
    prefix: <<215, 231, 2>>,
    name: "skein1024-952",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-952"), do: get(0xb3d7)
  
  def get(0xb3d8), do: %{
    code: 0xb3d8,
    prefix: <<216, 231, 2>>,
    name: "skein1024-960",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-960"), do: get(0xb3d8)
  
  def get(0xb3d9), do: %{
    code: 0xb3d9,
    prefix: <<217, 231, 2>>,
    name: "skein1024-968",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-968"), do: get(0xb3d9)
  
  def get(0xb3da), do: %{
    code: 0xb3da,
    prefix: <<218, 231, 2>>,
    name: "skein1024-976",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-976"), do: get(0xb3da)
  
  def get(0xb3db), do: %{
    code: 0xb3db,
    prefix: <<219, 231, 2>>,
    name: "skein1024-984",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-984"), do: get(0xb3db)
  
  def get(0xb3dc), do: %{
    code: 0xb3dc,
    prefix: <<220, 231, 2>>,
    name: "skein1024-992",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-992"), do: get(0xb3dc)
  
  def get(0xb3dd), do: %{
    code: 0xb3dd,
    prefix: <<221, 231, 2>>,
    name: "skein1024-1000",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-1000"), do: get(0xb3dd)
  
  def get(0xb3de), do: %{
    code: 0xb3de,
    prefix: <<222, 231, 2>>,
    name: "skein1024-1008",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-1008"), do: get(0xb3de)
  
  def get(0xb3df), do: %{
    code: 0xb3df,
    prefix: <<223, 231, 2>>,
    name: "skein1024-1016",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-1016"), do: get(0xb3df)
  
  def get(0xb3e0), do: %{
    code: 0xb3e0,
    prefix: <<224, 231, 2>>,
    name: "skein1024-1024",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("skein1024-1024"), do: get(0xb3e0)
  
  def get(0xb3e1), do: %{
    code: 0xb3e1,
    prefix: <<225, 231, 2>>,
    name: "xxh-32",
    description: "Extremely fast non-cryptographic hash algorithm",
    status: "draft",
    tag: "hash"
  }
  def get("xxh-32"), do: get(0xb3e1)
  
  def get(0xb3e2), do: %{
    code: 0xb3e2,
    prefix: <<226, 231, 2>>,
    name: "xxh-64",
    description: "Extremely fast non-cryptographic hash algorithm",
    status: "draft",
    tag: "hash"
  }
  def get("xxh-64"), do: get(0xb3e2)
  
  def get(0xb3e3), do: %{
    code: 0xb3e3,
    prefix: <<227, 231, 2>>,
    name: "xxh3-64",
    description: "Extremely fast non-cryptographic hash algorithm",
    status: "draft",
    tag: "hash"
  }
  def get("xxh3-64"), do: get(0xb3e3)
  
  def get(0xb3e4), do: %{
    code: 0xb3e4,
    prefix: <<228, 231, 2>>,
    name: "xxh3-128",
    description: "Extremely fast non-cryptographic hash algorithm",
    status: "draft",
    tag: "hash"
  }
  def get("xxh3-128"), do: get(0xb3e4)
  
  def get(0xb401), do: %{
    code: 0xb401,
    prefix: <<129, 232, 2>>,
    name: "poseidon-bls12_381-a2-fc1",
    description: "Poseidon using BLS12-381 and arity of 2 with Filecoin parameters",
    status: "permanent",
    tag: "multihash"
  }
  def get("poseidon-bls12_381-a2-fc1"), do: get(0xb401)
  
  def get(0xb402), do: %{
    code: 0xb402,
    prefix: <<130, 232, 2>>,
    name: "poseidon-bls12_381-a2-fc1-sc",
    description: "Poseidon using BLS12-381 and arity of 2 with Filecoin parameters - high-security variant",
    status: "draft",
    tag: "multihash"
  }
  def get("poseidon-bls12_381-a2-fc1-sc"), do: get(0xb402)
  
  def get(0xb403), do: %{
    code: 0xb403,
    prefix: <<131, 232, 2>>,
    name: "rdfc-1",
    description: "The result of canonicalizing an input according to RDFC-1.0 and then expressing its hash value as a multihash value.",
    status: "draft",
    tag: "ipld"
  }
  def get("rdfc-1"), do: get(0xb403)
  
  def get(0xb49910), do: %{
    code: 0xb49910,
    prefix: <<144, 178, 210, 5>>,
    name: "kumandra-ns",
    description: "Kumandra Network Namespace",
    status: "draft",
    tag: "namespace"
  }
  def get("kumandra-ns"), do: get(0xb49910)
  
  def get(0xb501), do: %{
    code: 0xb501,
    prefix: <<129, 234, 2>>,
    name: "ssz",
    description: "SimpleSerialize (SSZ) serialization",
    status: "draft",
    tag: "serialization"
  }
  def get("ssz"), do: get(0xb501)
  
  def get(0xb502), do: %{
    code: 0xb502,
    prefix: <<130, 234, 2>>,
    name: "ssz-sha2-256-bmt",
    description: "SSZ Merkle tree root using SHA2-256 as the hashing function and SSZ serialization for the block binary",
    status: "draft",
    tag: "multihash"
  }
  def get("ssz-sha2-256-bmt"), do: get(0xb502)
  
  def get(0xb510), do: %{
    code: 0xb510,
    prefix: <<144, 234, 2>>,
    name: "sha2-256-chunked",
    description: "Hash of concatenated SHA2-256 digests of 8*2^n MiB source chunks; n = ceil(log2(source_size/(10^4 * 8MiB)))",
    status: "draft",
    tag: "multihash"
  }
  def get("sha2-256-chunked"), do: get(0xb510)
  
  def get(0xb601), do: %{
    code: 0xb601,
    prefix: <<129, 236, 2>>,
    name: "json-jcs",
    description: "The result of canonicalizing an input according to JCS - JSON Canonicalisation Scheme (RFC 8785)",
    status: "draft",
    tag: "ipld"
  }
  def get("json-jcs"), do: get(0xb601)
  
  def get(0xc0), do: %{
    code: 0xc0,
    prefix: <<192, 1>>,
    name: "zcash-block",
    description: "Zcash Block",
    status: "permanent",
    tag: "ipld"
  }
  def get("zcash-block"), do: get(0xc0)
  
  def get(0xc1), do: %{
    code: 0xc1,
    prefix: <<193, 1>>,
    name: "zcash-tx",
    description: "Zcash Tx",
    status: "permanent",
    tag: "ipld"
  }
  def get("zcash-tx"), do: get(0xc1)
  
  def get(0xca), do: %{
    code: 0xca,
    prefix: <<202, 1>>,
    name: "caip-50",
    description: "CAIP-50 multi-chain account id",
    status: "draft",
    tag: "multiformat"
  }
  def get("caip-50"), do: get(0xca)
  
  def get(0xcc01), do: %{
    code: 0xcc01,
    prefix: <<129, 152, 3>>,
    name: "iscc",
    description: "ISCC (International Standard Content Code) - similarity preserving hash",
    status: "draft",
    tag: "softhash"
  }
  def get("iscc"), do: get(0xcc01)
  
  def get(0xce), do: %{
    code: 0xce,
    prefix: <<206, 1>>,
    name: "streamid",
    description: "Ceramic Stream Id",
    status: "draft",
    tag: "namespace"
  }
  def get("streamid"), do: get(0xce)
  
  def get(0xce11), do: %{
    code: 0xce11,
    prefix: <<145, 156, 3>>,
    name: "zeroxcert-imprint-256",
    description: "0xcert Asset Imprint (root hash)",
    status: "draft",
    tag: "zeroxcert"
  }
  def get("zeroxcert-imprint-256"), do: get(0xce11)
  
  def get(0xd0), do: %{
    code: 0xd0,
    prefix: <<208, 1>>,
    name: "stellar-block",
    description: "Stellar Block",
    status: "draft",
    tag: "ipld"
  }
  def get("stellar-block"), do: get(0xd0)
  
  def get(0xd000), do: %{
    code: 0xd000,
    prefix: <<128, 160, 3>>,
    name: "nonstandard-sig",
    description: "Namespace for all not yet standard signature algorithms",
    status: "deprecated",
    tag: "varsig"
  }
  def get("nonstandard-sig"), do: get(0xd000)
  
  def get(0xd00d), do: %{
    code: 0xd00d,
    prefix: <<141, 160, 3>>,
    name: "bcrypt-pbkdf",
    description: "Bcrypt-PBKDF key derivation function",
    status: "draft",
    tag: "multihash"
  }
  def get("bcrypt-pbkdf"), do: get(0xd00d)
  
  def get(0xd01200), do: %{
    code: 0xd01200,
    prefix: <<128, 164, 192, 6>>,
    name: "es256",
    description: "ES256 Signature Algorithm",
    status: "draft",
    tag: "varsig"
  }
  def get("es256"), do: get(0xd01200)
  
  def get(0xd01201), do: %{
    code: 0xd01201,
    prefix: <<129, 164, 192, 6>>,
    name: "es284",
    description: "ES384 Signature Algorithm",
    status: "draft",
    tag: "varsig"
  }
  def get("es284"), do: get(0xd01201)
  
  def get(0xd01202), do: %{
    code: 0xd01202,
    prefix: <<130, 164, 192, 6>>,
    name: "es512",
    description: "ES512 Signature Algorithm",
    status: "draft",
    tag: "varsig"
  }
  def get("es512"), do: get(0xd01202)
  
  def get(0xd01205), do: %{
    code: 0xd01205,
    prefix: <<133, 164, 192, 6>>,
    name: "rs256",
    description: "RS256 Signature Algorithm",
    status: "draft",
    tag: "varsig"
  }
  def get("rs256"), do: get(0xd01205)
  
  def get(0xd01300), do: %{
    code: 0xd01300,
    prefix: <<128, 166, 192, 6>>,
    name: "es256k-msig",
    description: "ES256K (secp256k1) Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("es256k-msig"), do: get(0xd01300)
  
  def get(0xd01301), do: %{
    code: 0xd01301,
    prefix: <<129, 166, 192, 6>>,
    name: "bls12_381-g1-msig",
    description: "G1 signature for BLS-12381-G2 as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("bls12_381-g1-msig"), do: get(0xd01301)
  
  def get(0xd01302), do: %{
    code: 0xd01302,
    prefix: <<130, 166, 192, 6>>,
    name: "bls12_381-g2-msig",
    description: "G2 signature for BLS-12381-G1 as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("bls12_381-g2-msig"), do: get(0xd01302)
  
  def get(0xd01303), do: %{
    code: 0xd01303,
    prefix: <<131, 166, 192, 6>>,
    name: "eddsa-msig",
    description: "Edwards-Curve Digital Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("eddsa-msig"), do: get(0xd01303)
  
  def get(0xd01304), do: %{
    code: 0xd01304,
    prefix: <<132, 166, 192, 6>>,
    name: "bls12_381-g1-share-msig",
    description: "G1 threshold signature share for BLS-12381-G2 as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("bls12_381-g1-share-msig"), do: get(0xd01304)
  
  def get(0xd01305), do: %{
    code: 0xd01305,
    prefix: <<133, 166, 192, 6>>,
    name: "bls12_381-g2-share-msig",
    description: "G2 threshold signature share for BLS-12381-G1 as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("bls12_381-g2-share-msig"), do: get(0xd01305)
  
  def get(0xd01306), do: %{
    code: 0xd01306,
    prefix: <<134, 166, 192, 6>>,
    name: "lamport-msig",
    description: "Lamport signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-msig"), do: get(0xd01306)
  
  def get(0xd01307), do: %{
    code: 0xd01307,
    prefix: <<135, 166, 192, 6>>,
    name: "lamport-share-msig",
    description: "Lamport threshold signature share as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("lamport-share-msig"), do: get(0xd01307)
  
  def get(0xd01308), do: %{
    code: 0xd01308,
    prefix: <<136, 166, 192, 6>>,
    name: "es256-msig",
    description: "ECDSA P-256 Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("es256-msig"), do: get(0xd01308)
  
  def get(0xd01309), do: %{
    code: 0xd01309,
    prefix: <<137, 166, 192, 6>>,
    name: "es384-msig",
    description: "ECDSA P-384 Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("es384-msig"), do: get(0xd01309)
  
  def get(0xd0130a), do: %{
    code: 0xd0130a,
    prefix: <<138, 166, 192, 6>>,
    name: "es521-msig",
    description: "ECDSA P-521 Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("es521-msig"), do: get(0xd0130a)
  
  def get(0xd0130b), do: %{
    code: 0xd0130b,
    prefix: <<139, 166, 192, 6>>,
    name: "rs256-msig",
    description: "RS256 Signature as Multisig",
    status: "draft",
    tag: "multisig"
  }
  def get("rs256-msig"), do: get(0xd0130b)
  
  def get(0xd02000), do: %{
    code: 0xd02000,
    prefix: <<128, 192, 192, 6>>,
    name: "scion",
    description: "SCION Internet architecture",
    status: "draft",
    tag: "multiaddr"
  }
  def get("scion"), do: get(0xd02000)
  
  def get(0xd0e7), do: %{
    code: 0xd0e7,
    prefix: <<231, 161, 3>>,
    name: "es256k",
    description: "ES256K Siganture Algorithm (secp256k1)",
    status: "draft",
    tag: "varsig"
  }
  def get("es256k"), do: get(0xd0e7)
  
  def get(0xd0ea), do: %{
    code: 0xd0ea,
    prefix: <<234, 161, 3>>,
    name: "bls12_381-g1-sig",
    description: "G1 signature for BLS12-381",
    status: "draft",
    tag: "varsig"
  }
  def get("bls12_381-g1-sig"), do: get(0xd0ea)
  
  def get(0xd0eb), do: %{
    code: 0xd0eb,
    prefix: <<235, 161, 3>>,
    name: "bls12_381-g2-sig",
    description: "G2 signature for BLS12-381",
    status: "draft",
    tag: "varsig"
  }
  def get("bls12_381-g2-sig"), do: get(0xd0eb)
  
  def get(0xd0ed), do: %{
    code: 0xd0ed,
    prefix: <<237, 161, 3>>,
    name: "eddsa",
    description: "Edwards-Curve Digital Signature Algorithm",
    status: "draft",
    tag: "varsig"
  }
  def get("eddsa"), do: get(0xd0ed)
  
  def get(0xd1), do: %{
    code: 0xd1,
    prefix: <<209, 1>>,
    name: "stellar-tx",
    description: "Stellar Tx",
    status: "draft",
    tag: "ipld"
  }
  def get("stellar-tx"), do: get(0xd1)
  
  def get(0xd191), do: %{
    code: 0xd191,
    prefix: <<145, 163, 3>>,
    name: "eip-191",
    description: "EIP-191 Ethereum Signed Data Standard",
    status: "draft",
    tag: "varsig"
  }
  def get("eip-191"), do: get(0xd191)
  
  def get(0xd4), do: %{
    code: 0xd4,
    prefix: <<212, 1>>,
    name: "md4",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("md4"), do: get(0xd4)
  
  def get(0xd5), do: %{
    code: 0xd5,
    prefix: <<213, 1>>,
    name: "md5",
    description: "",
    status: "draft",
    tag: "multihash"
  }
  def get("md5"), do: get(0xd5)
  
  def get(0xe0), do: %{
    code: 0xe0,
    prefix: <<224, 1>>,
    name: "decred-block",
    description: "Decred Block",
    status: "draft",
    tag: "ipld"
  }
  def get("decred-block"), do: get(0xe0)
  
  def get(0xe1), do: %{
    code: 0xe1,
    prefix: <<225, 1>>,
    name: "decred-tx",
    description: "Decred Tx",
    status: "draft",
    tag: "ipld"
  }
  def get("decred-tx"), do: get(0xe1)
  
  def get(0xe2), do: %{
    code: 0xe2,
    prefix: <<226, 1>>,
    name: "ipld",
    description: "IPLD path",
    status: "draft",
    tag: "namespace"
  }
  def get("ipld"), do: get(0xe2)
  
  def get(0xe3), do: %{
    code: 0xe3,
    prefix: <<227, 1>>,
    name: "ipfs",
    description: "IPFS path",
    status: "draft",
    tag: "namespace"
  }
  def get("ipfs"), do: get(0xe3)
  
  def get(0xe4), do: %{
    code: 0xe4,
    prefix: <<228, 1>>,
    name: "swarm",
    description: "Swarm path",
    status: "draft",
    tag: "namespace"
  }
  def get("swarm"), do: get(0xe4)
  
  def get(0xe5), do: %{
    code: 0xe5,
    prefix: <<229, 1>>,
    name: "ipns",
    description: "IPNS path",
    status: "draft",
    tag: "namespace"
  }
  def get("ipns"), do: get(0xe5)
  
  def get(0xe6), do: %{
    code: 0xe6,
    prefix: <<230, 1>>,
    name: "zeronet",
    description: "ZeroNet site address",
    status: "draft",
    tag: "namespace"
  }
  def get("zeronet"), do: get(0xe6)
  
  def get(0xe7), do: %{
    code: 0xe7,
    prefix: <<231, 1>>,
    name: "secp256k1-pub",
    description: "Secp256k1 public key (compressed)",
    status: "draft",
    tag: "key"
  }
  def get("secp256k1-pub"), do: get(0xe7)
  
  def get(0xe8), do: %{
    code: 0xe8,
    prefix: <<232, 1>>,
    name: "dnslink",
    description: "DNSLink path",
    status: "permanent",
    tag: "namespace"
  }
  def get("dnslink"), do: get(0xe8)
  
  def get(0xea), do: %{
    code: 0xea,
    prefix: <<234, 1>>,
    name: "bls12_381-g1-pub",
    description: "BLS12-381 public key in the G1 field",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1-pub"), do: get(0xea)
  
  def get(0xeb), do: %{
    code: 0xeb,
    prefix: <<235, 1>>,
    name: "bls12_381-g2-pub",
    description: "BLS12-381 public key in the G2 field",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g2-pub"), do: get(0xeb)
  
  def get(0xeb51), do: %{
    code: 0xeb51,
    prefix: <<209, 214, 3>>,
    name: "jwk_jcs-pub",
    description: "JSON object containing only the required members of a JWK (RFC 7518 and RFC 7517) representing the public key. Serialisation based on JCS (RFC 8785)",
    status: "draft",
    tag: "key"
  }
  def get("jwk_jcs-pub"), do: get(0xeb51)
  
  def get(0xec), do: %{
    code: 0xec,
    prefix: <<236, 1>>,
    name: "x25519-pub",
    description: "Curve25519 public key",
    status: "draft",
    tag: "key"
  }
  def get("x25519-pub"), do: get(0xec)
  
  def get(0xed), do: %{
    code: 0xed,
    prefix: <<237, 1>>,
    name: "ed25519-pub",
    description: "Ed25519 public key",
    status: "draft",
    tag: "key"
  }
  def get("ed25519-pub"), do: get(0xed)
  
  def get(0xee), do: %{
    code: 0xee,
    prefix: <<238, 1>>,
    name: "bls12_381-g1g2-pub",
    description: "BLS12-381 concatenated public keys in both the G1 and G2 fields",
    status: "draft",
    tag: "key"
  }
  def get("bls12_381-g1g2-pub"), do: get(0xee)
  
  def get(0xef), do: %{
    code: 0xef,
    prefix: <<239, 1>>,
    name: "sr25519-pub",
    description: "Sr25519 public key",
    status: "draft",
    tag: "key"
  }
  def get("sr25519-pub"), do: get(0xef)
  
  def get(0xf0), do: %{
    code: 0xf0,
    prefix: <<240, 1>>,
    name: "dash-block",
    description: "Dash Block",
    status: "draft",
    tag: "ipld"
  }
  def get("dash-block"), do: get(0xf0)
  
  def get(0xf1), do: %{
    code: 0xf1,
    prefix: <<241, 1>>,
    name: "dash-tx",
    description: "Dash Tx",
    status: "draft",
    tag: "ipld"
  }
  def get("dash-tx"), do: get(0xf1)
  
  def get(0xf101), do: %{
    code: 0xf101,
    prefix: <<129, 226, 3>>,
    name: "fil-commitment-unsealed",
    description: "Filecoin piece or sector data commitment merkle node/root (CommP & CommD)",
    status: "permanent",
    tag: "filecoin"
  }
  def get("fil-commitment-unsealed"), do: get(0xf101)
  
  def get(0xf102), do: %{
    code: 0xf102,
    prefix: <<130, 226, 3>>,
    name: "fil-commitment-sealed",
    description: "Filecoin sector data commitment merkle node/root - sealed and replicated (CommR)",
    status: "permanent",
    tag: "filecoin"
  }
  def get("fil-commitment-sealed"), do: get(0xf102)
  
  def get(0xfa), do: %{
    code: 0xfa,
    prefix: <<250, 1>>,
    name: "swarm-manifest",
    description: "Swarm Manifest",
    status: "draft",
    tag: "ipld"
  }
  def get("swarm-manifest"), do: get(0xfa)
  
  def get(0xfb), do: %{
    code: 0xfb,
    prefix: <<251, 1>>,
    name: "swarm-feed",
    description: "Swarm Feed",
    status: "draft",
    tag: "ipld"
  }
  def get("swarm-feed"), do: get(0xfb)
  
  def get(0xfc), do: %{
    code: 0xfc,
    prefix: <<252, 1>>,
    name: "beeson",
    description: "Swarm BeeSon",
    status: "draft",
    tag: "ipld"
  }
  def get("beeson"), do: get(0xfc)
  
  def get(_), do: nil

  @doc """
  Parse the codec prefix from a binary string. Returns a tuple in the form of `{codec_metadata, data}`. Will return `nil` if the prefix does not match any known codec.
  """
  @spec parse_prefix(binary()) :: {map(), binary()} | nil
  
  def parse_prefix(<<0>> <> rest), do: {get(0x00), rest}
  
  def parse_prefix(<<1>> <> rest), do: {get(0x01), rest}
  
  def parse_prefix(<<145, 2>> <> rest), do: {get(0x0111), rest}
  
  def parse_prefix(<<147, 2>> <> rest), do: {get(0x0113), rest}
  
  def parse_prefix(<<148, 2>> <> rest), do: {get(0x0114), rest}
  
  def parse_prefix(<<149, 2>> <> rest), do: {get(0x0115), rest}
  
  def parse_prefix(<<152, 2>> <> rest), do: {get(0x0118), rest}
  
  def parse_prefix(<<153, 2>> <> rest), do: {get(0x0119), rest}
  
  def parse_prefix(<<162, 2>> <> rest), do: {get(0x0122), rest}
  
  def parse_prefix(<<169, 2>> <> rest), do: {get(0x0129), rest}
  
  def parse_prefix(<<173, 2>> <> rest), do: {get(0x012d), rest}
  
  def parse_prefix(<<174, 2>> <> rest), do: {get(0x012e), rest}
  
  def parse_prefix(<<178, 2>> <> rest), do: {get(0x0132), rest}
  
  def parse_prefix(<<228, 2>> <> rest), do: {get(0x0164), rest}
  
  def parse_prefix(<<144, 3>> <> rest), do: {get(0x0190), rest}
  
  def parse_prefix(<<150, 3>> <> rest), do: {get(0x0196), rest}
  
  def parse_prefix(<<165, 3>> <> rest), do: {get(0x01a5), rest}
  
  def parse_prefix(<<187, 3>> <> rest), do: {get(0x01bb), rest}
  
  def parse_prefix(<<188, 3>> <> rest), do: {get(0x01bc), rest}
  
  def parse_prefix(<<189, 3>> <> rest), do: {get(0x01bd), rest}
  
  def parse_prefix(<<190, 3>> <> rest), do: {get(0x01be), rest}
  
  def parse_prefix(<<191, 3>> <> rest), do: {get(0x01bf), rest}
  
  def parse_prefix(<<192, 3>> <> rest), do: {get(0x01c0), rest}
  
  def parse_prefix(<<193, 3>> <> rest), do: {get(0x01c1), rest}
  
  def parse_prefix(<<198, 3>> <> rest), do: {get(0x01c6), rest}
  
  def parse_prefix(<<200, 3>> <> rest), do: {get(0x01c8), rest}
  
  def parse_prefix(<<204, 3>> <> rest), do: {get(0x01cc), rest}
  
  def parse_prefix(<<205, 3>> <> rest), do: {get(0x01cd), rest}
  
  def parse_prefix(<<209, 3>> <> rest), do: {get(0x01d1), rest}
  
  def parse_prefix(<<210, 3>> <> rest), do: {get(0x01d2), rest}
  
  def parse_prefix(<<221, 3>> <> rest), do: {get(0x01dd), rest}
  
  def parse_prefix(<<222, 3>> <> rest), do: {get(0x01de), rest}
  
  def parse_prefix(<<223, 3>> <> rest), do: {get(0x01df), rest}
  
  def parse_prefix(<<224, 3>> <> rest), do: {get(0x01e0), rest}
  
  def parse_prefix(<<225, 3>> <> rest), do: {get(0x01e1), rest}
  
  def parse_prefix(<<240, 3>> <> rest), do: {get(0x01f0), rest}
  
  def parse_prefix(<<2>> <> rest), do: {get(0x02), rest}
  
  def parse_prefix(<<128, 4>> <> rest), do: {get(0x0200), rest}
  
  def parse_prefix(<<129, 4>> <> rest), do: {get(0x0201), rest}
  
  def parse_prefix(<<130, 4>> <> rest), do: {get(0x0202), rest}
  
  def parse_prefix(<<3>> <> rest), do: {get(0x03), rest}
  
  def parse_prefix(<<128, 6>> <> rest), do: {get(0x0300), rest}
  
  def parse_prefix(<<129, 6>> <> rest), do: {get(0x0301), rest}
  
  def parse_prefix(<<130, 6>> <> rest), do: {get(0x0302), rest}
  
  def parse_prefix(<<137, 6>> <> rest), do: {get(0x0309), rest}
  
  def parse_prefix(<<4>> <> rest), do: {get(0x04), rest}
  
  def parse_prefix(<<128, 8>> <> rest), do: {get(0x0400), rest}
  
  def parse_prefix(<<129, 8>> <> rest), do: {get(0x0401), rest}
  
  def parse_prefix(<<6>> <> rest), do: {get(0x06), rest}
  
  def parse_prefix(<<128, 18>> <> rest), do: {get(0x0900), rest}
  
  def parse_prefix(<<144, 18>> <> rest), do: {get(0x0910), rest}
  
  def parse_prefix(<<160, 18>> <> rest), do: {get(0x0920), rest}
  
  def parse_prefix(<<157, 26>> <> rest), do: {get(0x0d1d), rest}
  
  def parse_prefix(<<146, 32>> <> rest), do: {get(0x1012), rest}
  
  def parse_prefix(<<147, 32>> <> rest), do: {get(0x1013), rest}
  
  def parse_prefix(<<148, 32>> <> rest), do: {get(0x1014), rest}
  
  def parse_prefix(<<149, 32>> <> rest), do: {get(0x1015), rest}
  
  def parse_prefix(<<162, 32>> <> rest), do: {get(0x1022), rest}
  
  def parse_prefix(<<210, 32>> <> rest), do: {get(0x1052), rest}
  
  def parse_prefix(<<211, 32>> <> rest), do: {get(0x1053), rest}
  
  def parse_prefix(<<212, 32>> <> rest), do: {get(0x1054), rest}
  
  def parse_prefix(<<213, 32>> <> rest), do: {get(0x1055), rest}
  
  def parse_prefix(<<17>> <> rest), do: {get(0x11), rest}
  
  def parse_prefix(<<128, 34>> <> rest), do: {get(0x1100), rest}
  
  def parse_prefix(<<18>> <> rest), do: {get(0x12), rest}
  
  def parse_prefix(<<128, 36>> <> rest), do: {get(0x1200), rest}
  
  def parse_prefix(<<129, 36>> <> rest), do: {get(0x1201), rest}
  
  def parse_prefix(<<130, 36>> <> rest), do: {get(0x1202), rest}
  
  def parse_prefix(<<131, 36>> <> rest), do: {get(0x1203), rest}
  
  def parse_prefix(<<132, 36>> <> rest), do: {get(0x1204), rest}
  
  def parse_prefix(<<133, 36>> <> rest), do: {get(0x1205), rest}
  
  def parse_prefix(<<134, 36>> <> rest), do: {get(0x1206), rest}
  
  def parse_prefix(<<135, 36>> <> rest), do: {get(0x1207), rest}
  
  def parse_prefix(<<136, 36>> <> rest), do: {get(0x1208), rest}
  
  def parse_prefix(<<137, 36>> <> rest), do: {get(0x1209), rest}
  
  def parse_prefix(<<138, 36>> <> rest), do: {get(0x120a), rest}
  
  def parse_prefix(<<139, 36>> <> rest), do: {get(0x120b), rest}
  
  def parse_prefix(<<140, 36>> <> rest), do: {get(0x120c), rest}
  
  def parse_prefix(<<141, 36>> <> rest), do: {get(0x120d), rest}
  
  def parse_prefix(<<185, 36>> <> rest), do: {get(0x1239), rest}
  
  def parse_prefix(<<186, 36>> <> rest), do: {get(0x123a), rest}
  
  def parse_prefix(<<187, 36>> <> rest), do: {get(0x123b), rest}
  
  def parse_prefix(<<19>> <> rest), do: {get(0x13), rest}
  
  def parse_prefix(<<128, 38>> <> rest), do: {get(0x1300), rest}
  
  def parse_prefix(<<129, 38>> <> rest), do: {get(0x1301), rest}
  
  def parse_prefix(<<130, 38>> <> rest), do: {get(0x1302), rest}
  
  def parse_prefix(<<131, 38>> <> rest), do: {get(0x1303), rest}
  
  def parse_prefix(<<133, 38>> <> rest), do: {get(0x1305), rest}
  
  def parse_prefix(<<134, 38>> <> rest), do: {get(0x1306), rest}
  
  def parse_prefix(<<135, 38>> <> rest), do: {get(0x1307), rest}
  
  def parse_prefix(<<136, 38>> <> rest), do: {get(0x1308), rest}
  
  def parse_prefix(<<137, 38>> <> rest), do: {get(0x1309), rest}
  
  def parse_prefix(<<138, 38>> <> rest), do: {get(0x130a), rest}
  
  def parse_prefix(<<139, 38>> <> rest), do: {get(0x130b), rest}
  
  def parse_prefix(<<140, 38>> <> rest), do: {get(0x130c), rest}
  
  def parse_prefix(<<141, 38>> <> rest), do: {get(0x130d), rest}
  
  def parse_prefix(<<142, 38>> <> rest), do: {get(0x130e), rest}
  
  def parse_prefix(<<143, 38>> <> rest), do: {get(0x130f), rest}
  
  def parse_prefix(<<144, 38>> <> rest), do: {get(0x1310), rest}
  
  def parse_prefix(<<20>> <> rest), do: {get(0x14), rest}
  
  def parse_prefix(<<21>> <> rest), do: {get(0x15), rest}
  
  def parse_prefix(<<22>> <> rest), do: {get(0x16), rest}
  
  def parse_prefix(<<23>> <> rest), do: {get(0x17), rest}
  
  def parse_prefix(<<24>> <> rest), do: {get(0x18), rest}
  
  def parse_prefix(<<25>> <> rest), do: {get(0x19), rest}
  
  def parse_prefix(<<26>> <> rest), do: {get(0x1a), rest}
  
  def parse_prefix(<<148, 52>> <> rest), do: {get(0x1a14), rest}
  
  def parse_prefix(<<149, 52>> <> rest), do: {get(0x1a15), rest}
  
  def parse_prefix(<<150, 52>> <> rest), do: {get(0x1a16), rest}
  
  def parse_prefix(<<164, 52>> <> rest), do: {get(0x1a24), rest}
  
  def parse_prefix(<<165, 52>> <> rest), do: {get(0x1a25), rest}
  
  def parse_prefix(<<166, 52>> <> rest), do: {get(0x1a26), rest}
  
  def parse_prefix(<<180, 52>> <> rest), do: {get(0x1a34), rest}
  
  def parse_prefix(<<181, 52>> <> rest), do: {get(0x1a35), rest}
  
  def parse_prefix(<<182, 52>> <> rest), do: {get(0x1a36), rest}
  
  def parse_prefix(<<196, 52>> <> rest), do: {get(0x1a44), rest}
  
  def parse_prefix(<<197, 52>> <> rest), do: {get(0x1a45), rest}
  
  def parse_prefix(<<198, 52>> <> rest), do: {get(0x1a46), rest}
  
  def parse_prefix(<<212, 52>> <> rest), do: {get(0x1a54), rest}
  
  def parse_prefix(<<213, 52>> <> rest), do: {get(0x1a55), rest}
  
  def parse_prefix(<<214, 52>> <> rest), do: {get(0x1a56), rest}
  
  def parse_prefix("\e" <> rest), do: {get(0x1b), rest}
  
  def parse_prefix(<<28>> <> rest), do: {get(0x1c), rest}
  
  def parse_prefix(<<29>> <> rest), do: {get(0x1d), rest}
  
  def parse_prefix(<<129, 58>> <> rest), do: {get(0x1d01), rest}
  
  def parse_prefix(<<30>> <> rest), do: {get(0x1e), rest}
  
  def parse_prefix(" " <> rest), do: {get(0x20), rest}
  
  def parse_prefix(<<128, 64>> <> rest), do: {get(0x2000), rest}
  
  def parse_prefix("!" <> rest), do: {get(0x21), rest}
  
  def parse_prefix("\"" <> rest), do: {get(0x22), rest}
  
  def parse_prefix("#" <> rest), do: {get(0x23), rest}
  
  def parse_prefix(")" <> rest), do: {get(0x29), rest}
  
  def parse_prefix("*" <> rest), do: {get(0x2a), rest}
  
  def parse_prefix("+" <> rest), do: {get(0x2b), rest}
  
  def parse_prefix("/" <> rest), do: {get(0x2f), rest}
  
  def parse_prefix("0" <> rest), do: {get(0x30), rest}
  
  def parse_prefix("1" <> rest), do: {get(0x31), rest}
  
  def parse_prefix("2" <> rest), do: {get(0x32), rest}
  
  def parse_prefix("3" <> rest), do: {get(0x33), rest}
  
  def parse_prefix("4" <> rest), do: {get(0x34), rest}
  
  def parse_prefix("5" <> rest), do: {get(0x35), rest}
  
  def parse_prefix("6" <> rest), do: {get(0x36), rest}
  
  def parse_prefix("7" <> rest), do: {get(0x37), rest}
  
  def parse_prefix("8" <> rest), do: {get(0x38), rest}
  
  def parse_prefix(<<194, 126>> <> rest), do: {get(0x3f42), rest}
  
  def parse_prefix("P" <> rest), do: {get(0x50), rest}
  
  def parse_prefix("Q" <> rest), do: {get(0x51), rest}
  
  def parse_prefix(<<128, 188, 196, 2>> <> rest), do: {get(0x511e00), rest}
  
  def parse_prefix(<<129, 188, 196, 2>> <> rest), do: {get(0x511e01), rest}
  
  def parse_prefix(<<130, 188, 196, 2>> <> rest), do: {get(0x511e02), rest}
  
  def parse_prefix(<<131, 188, 196, 2>> <> rest), do: {get(0x511e03), rest}
  
  def parse_prefix(<<132, 188, 196, 2>> <> rest), do: {get(0x511e04), rest}
  
  def parse_prefix(<<205, 166, 1>> <> rest), do: {get(0x534d), rest}
  
  def parse_prefix("U" <> rest), do: {get(0x55), rest}
  
  def parse_prefix("V" <> rest), do: {get(0x56), rest}
  
  def parse_prefix("`" <> rest), do: {get(0x60), rest}
  
  def parse_prefix("c" <> rest), do: {get(0x63), rest}
  
  def parse_prefix("p" <> rest), do: {get(0x70), rest}
  
  def parse_prefix(<<146, 224, 1>> <> rest), do: {get(0x7012), rest}
  
  def parse_prefix(<<225, 216, 193, 3>> <> rest), do: {get(0x706c61), rest}
  
  def parse_prefix("q" <> rest), do: {get(0x71), rest}
  
  def parse_prefix("r" <> rest), do: {get(0x72), rest}
  
  def parse_prefix("x" <> rest), do: {get(0x78), rest}
  
  def parse_prefix("{" <> rest), do: {get(0x7b), rest}
  
  def parse_prefix("|" <> rest), do: {get(0x7c), rest}
  
  def parse_prefix(<<128, 1>> <> rest), do: {get(0x80), rest}
  
  def parse_prefix(<<164, 226, 129, 4>> <> rest), do: {get(0x807124), rest}
  
  def parse_prefix(<<129, 1>> <> rest), do: {get(0x81), rest}
  
  def parse_prefix(<<164, 226, 133, 4>> <> rest), do: {get(0x817124), rest}
  
  def parse_prefix(<<130, 1>> <> rest), do: {get(0x82), rest}
  
  def parse_prefix(<<131, 1>> <> rest), do: {get(0x83), rest}
  
  def parse_prefix(<<132, 1>> <> rest), do: {get(0x84), rest}
  
  def parse_prefix(<<133, 1>> <> rest), do: {get(0x85), rest}
  
  def parse_prefix(<<134, 1>> <> rest), do: {get(0x86), rest}
  
  def parse_prefix(<<140, 1>> <> rest), do: {get(0x8c), rest}
  
  def parse_prefix(<<144, 1>> <> rest), do: {get(0x90), rest}
  
  def parse_prefix(<<145, 1>> <> rest), do: {get(0x91), rest}
  
  def parse_prefix(<<146, 1>> <> rest), do: {get(0x92), rest}
  
  def parse_prefix(<<147, 1>> <> rest), do: {get(0x93), rest}
  
  def parse_prefix(<<148, 1>> <> rest), do: {get(0x94), rest}
  
  def parse_prefix(<<164, 226, 209, 4>> <> rest), do: {get(0x947124), rest}
  
  def parse_prefix(<<149, 1>> <> rest), do: {get(0x95), rest}
  
  def parse_prefix(<<164, 226, 213, 4>> <> rest), do: {get(0x957124), rest}
  
  def parse_prefix(<<150, 1>> <> rest), do: {get(0x96), rest}
  
  def parse_prefix(<<151, 1>> <> rest), do: {get(0x97), rest}
  
  def parse_prefix(<<152, 1>> <> rest), do: {get(0x98), rest}
  
  def parse_prefix(<<153, 1>> <> rest), do: {get(0x99), rest}
  
  def parse_prefix(<<154, 1>> <> rest), do: {get(0x9a), rest}
  
  def parse_prefix(<<160, 1>> <> rest), do: {get(0xa0), rest}
  
  def parse_prefix(<<128, 192, 2>> <> rest), do: {get(0xa000), rest}
  
  def parse_prefix(<<161, 1>> <> rest), do: {get(0xa1), rest}
  
  def parse_prefix(<<162, 1>> <> rest), do: {get(0xa2), rest}
  
  def parse_prefix(<<164, 226, 137, 5>> <> rest), do: {get(0xa27124), rest}
  
  def parse_prefix(<<163, 1>> <> rest), do: {get(0xa3), rest}
  
  def parse_prefix(<<164, 226, 141, 5>> <> rest), do: {get(0xa37124), rest}
  
  def parse_prefix(<<164, 1>> <> rest), do: {get(0xa4), rest}
  
  def parse_prefix(<<176, 1>> <> rest), do: {get(0xb0), rest}
  
  def parse_prefix(<<177, 1>> <> rest), do: {get(0xb1), rest}
  
  def parse_prefix(<<144, 178, 198, 5>> <> rest), do: {get(0xb19910), rest}
  
  def parse_prefix(<<178, 1>> <> rest), do: {get(0xb2), rest}
  
  def parse_prefix(<<129, 228, 2>> <> rest), do: {get(0xb201), rest}
  
  def parse_prefix(<<130, 228, 2>> <> rest), do: {get(0xb202), rest}
  
  def parse_prefix(<<131, 228, 2>> <> rest), do: {get(0xb203), rest}
  
  def parse_prefix(<<132, 228, 2>> <> rest), do: {get(0xb204), rest}
  
  def parse_prefix(<<133, 228, 2>> <> rest), do: {get(0xb205), rest}
  
  def parse_prefix(<<134, 228, 2>> <> rest), do: {get(0xb206), rest}
  
  def parse_prefix(<<135, 228, 2>> <> rest), do: {get(0xb207), rest}
  
  def parse_prefix(<<136, 228, 2>> <> rest), do: {get(0xb208), rest}
  
  def parse_prefix(<<137, 228, 2>> <> rest), do: {get(0xb209), rest}
  
  def parse_prefix(<<138, 228, 2>> <> rest), do: {get(0xb20a), rest}
  
  def parse_prefix(<<139, 228, 2>> <> rest), do: {get(0xb20b), rest}
  
  def parse_prefix(<<140, 228, 2>> <> rest), do: {get(0xb20c), rest}
  
  def parse_prefix(<<141, 228, 2>> <> rest), do: {get(0xb20d), rest}
  
  def parse_prefix(<<142, 228, 2>> <> rest), do: {get(0xb20e), rest}
  
  def parse_prefix(<<143, 228, 2>> <> rest), do: {get(0xb20f), rest}
  
  def parse_prefix(<<144, 228, 2>> <> rest), do: {get(0xb210), rest}
  
  def parse_prefix(<<145, 228, 2>> <> rest), do: {get(0xb211), rest}
  
  def parse_prefix(<<146, 228, 2>> <> rest), do: {get(0xb212), rest}
  
  def parse_prefix(<<147, 228, 2>> <> rest), do: {get(0xb213), rest}
  
  def parse_prefix(<<148, 228, 2>> <> rest), do: {get(0xb214), rest}
  
  def parse_prefix(<<149, 228, 2>> <> rest), do: {get(0xb215), rest}
  
  def parse_prefix(<<150, 228, 2>> <> rest), do: {get(0xb216), rest}
  
  def parse_prefix(<<151, 228, 2>> <> rest), do: {get(0xb217), rest}
  
  def parse_prefix(<<152, 228, 2>> <> rest), do: {get(0xb218), rest}
  
  def parse_prefix(<<153, 228, 2>> <> rest), do: {get(0xb219), rest}
  
  def parse_prefix(<<154, 228, 2>> <> rest), do: {get(0xb21a), rest}
  
  def parse_prefix(<<155, 228, 2>> <> rest), do: {get(0xb21b), rest}
  
  def parse_prefix(<<156, 228, 2>> <> rest), do: {get(0xb21c), rest}
  
  def parse_prefix(<<157, 228, 2>> <> rest), do: {get(0xb21d), rest}
  
  def parse_prefix(<<158, 228, 2>> <> rest), do: {get(0xb21e), rest}
  
  def parse_prefix(<<159, 228, 2>> <> rest), do: {get(0xb21f), rest}
  
  def parse_prefix(<<160, 228, 2>> <> rest), do: {get(0xb220), rest}
  
  def parse_prefix(<<161, 228, 2>> <> rest), do: {get(0xb221), rest}
  
  def parse_prefix(<<162, 228, 2>> <> rest), do: {get(0xb222), rest}
  
  def parse_prefix(<<163, 228, 2>> <> rest), do: {get(0xb223), rest}
  
  def parse_prefix(<<164, 228, 2>> <> rest), do: {get(0xb224), rest}
  
  def parse_prefix(<<165, 228, 2>> <> rest), do: {get(0xb225), rest}
  
  def parse_prefix(<<166, 228, 2>> <> rest), do: {get(0xb226), rest}
  
  def parse_prefix(<<167, 228, 2>> <> rest), do: {get(0xb227), rest}
  
  def parse_prefix(<<168, 228, 2>> <> rest), do: {get(0xb228), rest}
  
  def parse_prefix(<<169, 228, 2>> <> rest), do: {get(0xb229), rest}
  
  def parse_prefix(<<170, 228, 2>> <> rest), do: {get(0xb22a), rest}
  
  def parse_prefix(<<171, 228, 2>> <> rest), do: {get(0xb22b), rest}
  
  def parse_prefix(<<172, 228, 2>> <> rest), do: {get(0xb22c), rest}
  
  def parse_prefix(<<173, 228, 2>> <> rest), do: {get(0xb22d), rest}
  
  def parse_prefix(<<174, 228, 2>> <> rest), do: {get(0xb22e), rest}
  
  def parse_prefix(<<175, 228, 2>> <> rest), do: {get(0xb22f), rest}
  
  def parse_prefix(<<176, 228, 2>> <> rest), do: {get(0xb230), rest}
  
  def parse_prefix(<<177, 228, 2>> <> rest), do: {get(0xb231), rest}
  
  def parse_prefix(<<178, 228, 2>> <> rest), do: {get(0xb232), rest}
  
  def parse_prefix(<<179, 228, 2>> <> rest), do: {get(0xb233), rest}
  
  def parse_prefix(<<180, 228, 2>> <> rest), do: {get(0xb234), rest}
  
  def parse_prefix(<<181, 228, 2>> <> rest), do: {get(0xb235), rest}
  
  def parse_prefix(<<182, 228, 2>> <> rest), do: {get(0xb236), rest}
  
  def parse_prefix(<<183, 228, 2>> <> rest), do: {get(0xb237), rest}
  
  def parse_prefix(<<184, 228, 2>> <> rest), do: {get(0xb238), rest}
  
  def parse_prefix(<<185, 228, 2>> <> rest), do: {get(0xb239), rest}
  
  def parse_prefix(<<186, 228, 2>> <> rest), do: {get(0xb23a), rest}
  
  def parse_prefix(<<187, 228, 2>> <> rest), do: {get(0xb23b), rest}
  
  def parse_prefix(<<188, 228, 2>> <> rest), do: {get(0xb23c), rest}
  
  def parse_prefix(<<189, 228, 2>> <> rest), do: {get(0xb23d), rest}
  
  def parse_prefix(<<190, 228, 2>> <> rest), do: {get(0xb23e), rest}
  
  def parse_prefix(<<191, 228, 2>> <> rest), do: {get(0xb23f), rest}
  
  def parse_prefix(<<192, 228, 2>> <> rest), do: {get(0xb240), rest}
  
  def parse_prefix(<<193, 228, 2>> <> rest), do: {get(0xb241), rest}
  
  def parse_prefix(<<194, 228, 2>> <> rest), do: {get(0xb242), rest}
  
  def parse_prefix(<<195, 228, 2>> <> rest), do: {get(0xb243), rest}
  
  def parse_prefix(<<196, 228, 2>> <> rest), do: {get(0xb244), rest}
  
  def parse_prefix(<<197, 228, 2>> <> rest), do: {get(0xb245), rest}
  
  def parse_prefix(<<198, 228, 2>> <> rest), do: {get(0xb246), rest}
  
  def parse_prefix(<<199, 228, 2>> <> rest), do: {get(0xb247), rest}
  
  def parse_prefix(<<200, 228, 2>> <> rest), do: {get(0xb248), rest}
  
  def parse_prefix(<<201, 228, 2>> <> rest), do: {get(0xb249), rest}
  
  def parse_prefix(<<202, 228, 2>> <> rest), do: {get(0xb24a), rest}
  
  def parse_prefix(<<203, 228, 2>> <> rest), do: {get(0xb24b), rest}
  
  def parse_prefix(<<204, 228, 2>> <> rest), do: {get(0xb24c), rest}
  
  def parse_prefix(<<205, 228, 2>> <> rest), do: {get(0xb24d), rest}
  
  def parse_prefix(<<206, 228, 2>> <> rest), do: {get(0xb24e), rest}
  
  def parse_prefix(<<207, 228, 2>> <> rest), do: {get(0xb24f), rest}
  
  def parse_prefix(<<208, 228, 2>> <> rest), do: {get(0xb250), rest}
  
  def parse_prefix(<<209, 228, 2>> <> rest), do: {get(0xb251), rest}
  
  def parse_prefix(<<210, 228, 2>> <> rest), do: {get(0xb252), rest}
  
  def parse_prefix(<<211, 228, 2>> <> rest), do: {get(0xb253), rest}
  
  def parse_prefix(<<212, 228, 2>> <> rest), do: {get(0xb254), rest}
  
  def parse_prefix(<<213, 228, 2>> <> rest), do: {get(0xb255), rest}
  
  def parse_prefix(<<214, 228, 2>> <> rest), do: {get(0xb256), rest}
  
  def parse_prefix(<<215, 228, 2>> <> rest), do: {get(0xb257), rest}
  
  def parse_prefix(<<216, 228, 2>> <> rest), do: {get(0xb258), rest}
  
  def parse_prefix(<<217, 228, 2>> <> rest), do: {get(0xb259), rest}
  
  def parse_prefix(<<218, 228, 2>> <> rest), do: {get(0xb25a), rest}
  
  def parse_prefix(<<219, 228, 2>> <> rest), do: {get(0xb25b), rest}
  
  def parse_prefix(<<220, 228, 2>> <> rest), do: {get(0xb25c), rest}
  
  def parse_prefix(<<221, 228, 2>> <> rest), do: {get(0xb25d), rest}
  
  def parse_prefix(<<222, 228, 2>> <> rest), do: {get(0xb25e), rest}
  
  def parse_prefix(<<223, 228, 2>> <> rest), do: {get(0xb25f), rest}
  
  def parse_prefix(<<224, 228, 2>> <> rest), do: {get(0xb260), rest}
  
  def parse_prefix(<<144, 178, 202, 5>> <> rest), do: {get(0xb29910), rest}
  
  def parse_prefix(<<129, 230, 2>> <> rest), do: {get(0xb301), rest}
  
  def parse_prefix(<<130, 230, 2>> <> rest), do: {get(0xb302), rest}
  
  def parse_prefix(<<131, 230, 2>> <> rest), do: {get(0xb303), rest}
  
  def parse_prefix(<<132, 230, 2>> <> rest), do: {get(0xb304), rest}
  
  def parse_prefix(<<133, 230, 2>> <> rest), do: {get(0xb305), rest}
  
  def parse_prefix(<<134, 230, 2>> <> rest), do: {get(0xb306), rest}
  
  def parse_prefix(<<135, 230, 2>> <> rest), do: {get(0xb307), rest}
  
  def parse_prefix(<<136, 230, 2>> <> rest), do: {get(0xb308), rest}
  
  def parse_prefix(<<137, 230, 2>> <> rest), do: {get(0xb309), rest}
  
  def parse_prefix(<<138, 230, 2>> <> rest), do: {get(0xb30a), rest}
  
  def parse_prefix(<<139, 230, 2>> <> rest), do: {get(0xb30b), rest}
  
  def parse_prefix(<<140, 230, 2>> <> rest), do: {get(0xb30c), rest}
  
  def parse_prefix(<<141, 230, 2>> <> rest), do: {get(0xb30d), rest}
  
  def parse_prefix(<<142, 230, 2>> <> rest), do: {get(0xb30e), rest}
  
  def parse_prefix(<<143, 230, 2>> <> rest), do: {get(0xb30f), rest}
  
  def parse_prefix(<<144, 230, 2>> <> rest), do: {get(0xb310), rest}
  
  def parse_prefix(<<145, 230, 2>> <> rest), do: {get(0xb311), rest}
  
  def parse_prefix(<<146, 230, 2>> <> rest), do: {get(0xb312), rest}
  
  def parse_prefix(<<147, 230, 2>> <> rest), do: {get(0xb313), rest}
  
  def parse_prefix(<<148, 230, 2>> <> rest), do: {get(0xb314), rest}
  
  def parse_prefix(<<149, 230, 2>> <> rest), do: {get(0xb315), rest}
  
  def parse_prefix(<<150, 230, 2>> <> rest), do: {get(0xb316), rest}
  
  def parse_prefix(<<151, 230, 2>> <> rest), do: {get(0xb317), rest}
  
  def parse_prefix(<<152, 230, 2>> <> rest), do: {get(0xb318), rest}
  
  def parse_prefix(<<153, 230, 2>> <> rest), do: {get(0xb319), rest}
  
  def parse_prefix(<<154, 230, 2>> <> rest), do: {get(0xb31a), rest}
  
  def parse_prefix(<<155, 230, 2>> <> rest), do: {get(0xb31b), rest}
  
  def parse_prefix(<<156, 230, 2>> <> rest), do: {get(0xb31c), rest}
  
  def parse_prefix(<<157, 230, 2>> <> rest), do: {get(0xb31d), rest}
  
  def parse_prefix(<<158, 230, 2>> <> rest), do: {get(0xb31e), rest}
  
  def parse_prefix(<<159, 230, 2>> <> rest), do: {get(0xb31f), rest}
  
  def parse_prefix(<<160, 230, 2>> <> rest), do: {get(0xb320), rest}
  
  def parse_prefix(<<161, 230, 2>> <> rest), do: {get(0xb321), rest}
  
  def parse_prefix(<<162, 230, 2>> <> rest), do: {get(0xb322), rest}
  
  def parse_prefix(<<163, 230, 2>> <> rest), do: {get(0xb323), rest}
  
  def parse_prefix(<<164, 230, 2>> <> rest), do: {get(0xb324), rest}
  
  def parse_prefix(<<165, 230, 2>> <> rest), do: {get(0xb325), rest}
  
  def parse_prefix(<<166, 230, 2>> <> rest), do: {get(0xb326), rest}
  
  def parse_prefix(<<167, 230, 2>> <> rest), do: {get(0xb327), rest}
  
  def parse_prefix(<<168, 230, 2>> <> rest), do: {get(0xb328), rest}
  
  def parse_prefix(<<169, 230, 2>> <> rest), do: {get(0xb329), rest}
  
  def parse_prefix(<<170, 230, 2>> <> rest), do: {get(0xb32a), rest}
  
  def parse_prefix(<<171, 230, 2>> <> rest), do: {get(0xb32b), rest}
  
  def parse_prefix(<<172, 230, 2>> <> rest), do: {get(0xb32c), rest}
  
  def parse_prefix(<<173, 230, 2>> <> rest), do: {get(0xb32d), rest}
  
  def parse_prefix(<<174, 230, 2>> <> rest), do: {get(0xb32e), rest}
  
  def parse_prefix(<<175, 230, 2>> <> rest), do: {get(0xb32f), rest}
  
  def parse_prefix(<<176, 230, 2>> <> rest), do: {get(0xb330), rest}
  
  def parse_prefix(<<177, 230, 2>> <> rest), do: {get(0xb331), rest}
  
  def parse_prefix(<<178, 230, 2>> <> rest), do: {get(0xb332), rest}
  
  def parse_prefix(<<179, 230, 2>> <> rest), do: {get(0xb333), rest}
  
  def parse_prefix(<<180, 230, 2>> <> rest), do: {get(0xb334), rest}
  
  def parse_prefix(<<181, 230, 2>> <> rest), do: {get(0xb335), rest}
  
  def parse_prefix(<<182, 230, 2>> <> rest), do: {get(0xb336), rest}
  
  def parse_prefix(<<183, 230, 2>> <> rest), do: {get(0xb337), rest}
  
  def parse_prefix(<<184, 230, 2>> <> rest), do: {get(0xb338), rest}
  
  def parse_prefix(<<185, 230, 2>> <> rest), do: {get(0xb339), rest}
  
  def parse_prefix(<<186, 230, 2>> <> rest), do: {get(0xb33a), rest}
  
  def parse_prefix(<<187, 230, 2>> <> rest), do: {get(0xb33b), rest}
  
  def parse_prefix(<<188, 230, 2>> <> rest), do: {get(0xb33c), rest}
  
  def parse_prefix(<<189, 230, 2>> <> rest), do: {get(0xb33d), rest}
  
  def parse_prefix(<<190, 230, 2>> <> rest), do: {get(0xb33e), rest}
  
  def parse_prefix(<<191, 230, 2>> <> rest), do: {get(0xb33f), rest}
  
  def parse_prefix(<<192, 230, 2>> <> rest), do: {get(0xb340), rest}
  
  def parse_prefix(<<193, 230, 2>> <> rest), do: {get(0xb341), rest}
  
  def parse_prefix(<<194, 230, 2>> <> rest), do: {get(0xb342), rest}
  
  def parse_prefix(<<195, 230, 2>> <> rest), do: {get(0xb343), rest}
  
  def parse_prefix(<<196, 230, 2>> <> rest), do: {get(0xb344), rest}
  
  def parse_prefix(<<197, 230, 2>> <> rest), do: {get(0xb345), rest}
  
  def parse_prefix(<<198, 230, 2>> <> rest), do: {get(0xb346), rest}
  
  def parse_prefix(<<199, 230, 2>> <> rest), do: {get(0xb347), rest}
  
  def parse_prefix(<<200, 230, 2>> <> rest), do: {get(0xb348), rest}
  
  def parse_prefix(<<201, 230, 2>> <> rest), do: {get(0xb349), rest}
  
  def parse_prefix(<<202, 230, 2>> <> rest), do: {get(0xb34a), rest}
  
  def parse_prefix(<<203, 230, 2>> <> rest), do: {get(0xb34b), rest}
  
  def parse_prefix(<<204, 230, 2>> <> rest), do: {get(0xb34c), rest}
  
  def parse_prefix(<<205, 230, 2>> <> rest), do: {get(0xb34d), rest}
  
  def parse_prefix(<<206, 230, 2>> <> rest), do: {get(0xb34e), rest}
  
  def parse_prefix(<<207, 230, 2>> <> rest), do: {get(0xb34f), rest}
  
  def parse_prefix(<<208, 230, 2>> <> rest), do: {get(0xb350), rest}
  
  def parse_prefix(<<209, 230, 2>> <> rest), do: {get(0xb351), rest}
  
  def parse_prefix(<<210, 230, 2>> <> rest), do: {get(0xb352), rest}
  
  def parse_prefix(<<211, 230, 2>> <> rest), do: {get(0xb353), rest}
  
  def parse_prefix(<<212, 230, 2>> <> rest), do: {get(0xb354), rest}
  
  def parse_prefix(<<213, 230, 2>> <> rest), do: {get(0xb355), rest}
  
  def parse_prefix(<<214, 230, 2>> <> rest), do: {get(0xb356), rest}
  
  def parse_prefix(<<215, 230, 2>> <> rest), do: {get(0xb357), rest}
  
  def parse_prefix(<<216, 230, 2>> <> rest), do: {get(0xb358), rest}
  
  def parse_prefix(<<217, 230, 2>> <> rest), do: {get(0xb359), rest}
  
  def parse_prefix(<<218, 230, 2>> <> rest), do: {get(0xb35a), rest}
  
  def parse_prefix(<<219, 230, 2>> <> rest), do: {get(0xb35b), rest}
  
  def parse_prefix(<<220, 230, 2>> <> rest), do: {get(0xb35c), rest}
  
  def parse_prefix(<<221, 230, 2>> <> rest), do: {get(0xb35d), rest}
  
  def parse_prefix(<<222, 230, 2>> <> rest), do: {get(0xb35e), rest}
  
  def parse_prefix(<<223, 230, 2>> <> rest), do: {get(0xb35f), rest}
  
  def parse_prefix(<<224, 230, 2>> <> rest), do: {get(0xb360), rest}
  
  def parse_prefix(<<225, 230, 2>> <> rest), do: {get(0xb361), rest}
  
  def parse_prefix(<<226, 230, 2>> <> rest), do: {get(0xb362), rest}
  
  def parse_prefix(<<227, 230, 2>> <> rest), do: {get(0xb363), rest}
  
  def parse_prefix(<<228, 230, 2>> <> rest), do: {get(0xb364), rest}
  
  def parse_prefix(<<229, 230, 2>> <> rest), do: {get(0xb365), rest}
  
  def parse_prefix(<<230, 230, 2>> <> rest), do: {get(0xb366), rest}
  
  def parse_prefix(<<231, 230, 2>> <> rest), do: {get(0xb367), rest}
  
  def parse_prefix(<<232, 230, 2>> <> rest), do: {get(0xb368), rest}
  
  def parse_prefix(<<233, 230, 2>> <> rest), do: {get(0xb369), rest}
  
  def parse_prefix(<<234, 230, 2>> <> rest), do: {get(0xb36a), rest}
  
  def parse_prefix(<<235, 230, 2>> <> rest), do: {get(0xb36b), rest}
  
  def parse_prefix(<<236, 230, 2>> <> rest), do: {get(0xb36c), rest}
  
  def parse_prefix(<<237, 230, 2>> <> rest), do: {get(0xb36d), rest}
  
  def parse_prefix(<<238, 230, 2>> <> rest), do: {get(0xb36e), rest}
  
  def parse_prefix(<<239, 230, 2>> <> rest), do: {get(0xb36f), rest}
  
  def parse_prefix(<<240, 230, 2>> <> rest), do: {get(0xb370), rest}
  
  def parse_prefix(<<241, 230, 2>> <> rest), do: {get(0xb371), rest}
  
  def parse_prefix(<<242, 230, 2>> <> rest), do: {get(0xb372), rest}
  
  def parse_prefix(<<243, 230, 2>> <> rest), do: {get(0xb373), rest}
  
  def parse_prefix(<<244, 230, 2>> <> rest), do: {get(0xb374), rest}
  
  def parse_prefix(<<245, 230, 2>> <> rest), do: {get(0xb375), rest}
  
  def parse_prefix(<<246, 230, 2>> <> rest), do: {get(0xb376), rest}
  
  def parse_prefix(<<247, 230, 2>> <> rest), do: {get(0xb377), rest}
  
  def parse_prefix(<<248, 230, 2>> <> rest), do: {get(0xb378), rest}
  
  def parse_prefix(<<249, 230, 2>> <> rest), do: {get(0xb379), rest}
  
  def parse_prefix(<<250, 230, 2>> <> rest), do: {get(0xb37a), rest}
  
  def parse_prefix(<<251, 230, 2>> <> rest), do: {get(0xb37b), rest}
  
  def parse_prefix(<<252, 230, 2>> <> rest), do: {get(0xb37c), rest}
  
  def parse_prefix(<<253, 230, 2>> <> rest), do: {get(0xb37d), rest}
  
  def parse_prefix(<<254, 230, 2>> <> rest), do: {get(0xb37e), rest}
  
  def parse_prefix(<<255, 230, 2>> <> rest), do: {get(0xb37f), rest}
  
  def parse_prefix(<<128, 231, 2>> <> rest), do: {get(0xb380), rest}
  
  def parse_prefix(<<129, 231, 2>> <> rest), do: {get(0xb381), rest}
  
  def parse_prefix(<<130, 231, 2>> <> rest), do: {get(0xb382), rest}
  
  def parse_prefix(<<131, 231, 2>> <> rest), do: {get(0xb383), rest}
  
  def parse_prefix(<<132, 231, 2>> <> rest), do: {get(0xb384), rest}
  
  def parse_prefix(<<133, 231, 2>> <> rest), do: {get(0xb385), rest}
  
  def parse_prefix(<<134, 231, 2>> <> rest), do: {get(0xb386), rest}
  
  def parse_prefix(<<135, 231, 2>> <> rest), do: {get(0xb387), rest}
  
  def parse_prefix(<<136, 231, 2>> <> rest), do: {get(0xb388), rest}
  
  def parse_prefix(<<137, 231, 2>> <> rest), do: {get(0xb389), rest}
  
  def parse_prefix(<<138, 231, 2>> <> rest), do: {get(0xb38a), rest}
  
  def parse_prefix(<<139, 231, 2>> <> rest), do: {get(0xb38b), rest}
  
  def parse_prefix(<<140, 231, 2>> <> rest), do: {get(0xb38c), rest}
  
  def parse_prefix(<<141, 231, 2>> <> rest), do: {get(0xb38d), rest}
  
  def parse_prefix(<<142, 231, 2>> <> rest), do: {get(0xb38e), rest}
  
  def parse_prefix(<<143, 231, 2>> <> rest), do: {get(0xb38f), rest}
  
  def parse_prefix(<<144, 231, 2>> <> rest), do: {get(0xb390), rest}
  
  def parse_prefix(<<145, 231, 2>> <> rest), do: {get(0xb391), rest}
  
  def parse_prefix(<<146, 231, 2>> <> rest), do: {get(0xb392), rest}
  
  def parse_prefix(<<147, 231, 2>> <> rest), do: {get(0xb393), rest}
  
  def parse_prefix(<<148, 231, 2>> <> rest), do: {get(0xb394), rest}
  
  def parse_prefix(<<149, 231, 2>> <> rest), do: {get(0xb395), rest}
  
  def parse_prefix(<<150, 231, 2>> <> rest), do: {get(0xb396), rest}
  
  def parse_prefix(<<151, 231, 2>> <> rest), do: {get(0xb397), rest}
  
  def parse_prefix(<<152, 231, 2>> <> rest), do: {get(0xb398), rest}
  
  def parse_prefix(<<153, 231, 2>> <> rest), do: {get(0xb399), rest}
  
  def parse_prefix(<<144, 178, 206, 5>> <> rest), do: {get(0xb39910), rest}
  
  def parse_prefix(<<154, 231, 2>> <> rest), do: {get(0xb39a), rest}
  
  def parse_prefix(<<155, 231, 2>> <> rest), do: {get(0xb39b), rest}
  
  def parse_prefix(<<156, 231, 2>> <> rest), do: {get(0xb39c), rest}
  
  def parse_prefix(<<157, 231, 2>> <> rest), do: {get(0xb39d), rest}
  
  def parse_prefix(<<158, 231, 2>> <> rest), do: {get(0xb39e), rest}
  
  def parse_prefix(<<159, 231, 2>> <> rest), do: {get(0xb39f), rest}
  
  def parse_prefix(<<160, 231, 2>> <> rest), do: {get(0xb3a0), rest}
  
  def parse_prefix(<<161, 231, 2>> <> rest), do: {get(0xb3a1), rest}
  
  def parse_prefix(<<162, 231, 2>> <> rest), do: {get(0xb3a2), rest}
  
  def parse_prefix(<<163, 231, 2>> <> rest), do: {get(0xb3a3), rest}
  
  def parse_prefix(<<164, 231, 2>> <> rest), do: {get(0xb3a4), rest}
  
  def parse_prefix(<<165, 231, 2>> <> rest), do: {get(0xb3a5), rest}
  
  def parse_prefix(<<166, 231, 2>> <> rest), do: {get(0xb3a6), rest}
  
  def parse_prefix(<<167, 231, 2>> <> rest), do: {get(0xb3a7), rest}
  
  def parse_prefix(<<168, 231, 2>> <> rest), do: {get(0xb3a8), rest}
  
  def parse_prefix(<<169, 231, 2>> <> rest), do: {get(0xb3a9), rest}
  
  def parse_prefix(<<170, 231, 2>> <> rest), do: {get(0xb3aa), rest}
  
  def parse_prefix(<<171, 231, 2>> <> rest), do: {get(0xb3ab), rest}
  
  def parse_prefix(<<172, 231, 2>> <> rest), do: {get(0xb3ac), rest}
  
  def parse_prefix(<<173, 231, 2>> <> rest), do: {get(0xb3ad), rest}
  
  def parse_prefix(<<174, 231, 2>> <> rest), do: {get(0xb3ae), rest}
  
  def parse_prefix(<<175, 231, 2>> <> rest), do: {get(0xb3af), rest}
  
  def parse_prefix(<<176, 231, 2>> <> rest), do: {get(0xb3b0), rest}
  
  def parse_prefix(<<177, 231, 2>> <> rest), do: {get(0xb3b1), rest}
  
  def parse_prefix(<<178, 231, 2>> <> rest), do: {get(0xb3b2), rest}
  
  def parse_prefix(<<179, 231, 2>> <> rest), do: {get(0xb3b3), rest}
  
  def parse_prefix(<<180, 231, 2>> <> rest), do: {get(0xb3b4), rest}
  
  def parse_prefix(<<181, 231, 2>> <> rest), do: {get(0xb3b5), rest}
  
  def parse_prefix(<<182, 231, 2>> <> rest), do: {get(0xb3b6), rest}
  
  def parse_prefix(<<183, 231, 2>> <> rest), do: {get(0xb3b7), rest}
  
  def parse_prefix(<<184, 231, 2>> <> rest), do: {get(0xb3b8), rest}
  
  def parse_prefix(<<185, 231, 2>> <> rest), do: {get(0xb3b9), rest}
  
  def parse_prefix(<<186, 231, 2>> <> rest), do: {get(0xb3ba), rest}
  
  def parse_prefix(<<187, 231, 2>> <> rest), do: {get(0xb3bb), rest}
  
  def parse_prefix(<<188, 231, 2>> <> rest), do: {get(0xb3bc), rest}
  
  def parse_prefix(<<189, 231, 2>> <> rest), do: {get(0xb3bd), rest}
  
  def parse_prefix(<<190, 231, 2>> <> rest), do: {get(0xb3be), rest}
  
  def parse_prefix(<<191, 231, 2>> <> rest), do: {get(0xb3bf), rest}
  
  def parse_prefix(<<192, 231, 2>> <> rest), do: {get(0xb3c0), rest}
  
  def parse_prefix(<<193, 231, 2>> <> rest), do: {get(0xb3c1), rest}
  
  def parse_prefix(<<194, 231, 2>> <> rest), do: {get(0xb3c2), rest}
  
  def parse_prefix(<<195, 231, 2>> <> rest), do: {get(0xb3c3), rest}
  
  def parse_prefix(<<196, 231, 2>> <> rest), do: {get(0xb3c4), rest}
  
  def parse_prefix(<<197, 231, 2>> <> rest), do: {get(0xb3c5), rest}
  
  def parse_prefix(<<198, 231, 2>> <> rest), do: {get(0xb3c6), rest}
  
  def parse_prefix(<<199, 231, 2>> <> rest), do: {get(0xb3c7), rest}
  
  def parse_prefix(<<200, 231, 2>> <> rest), do: {get(0xb3c8), rest}
  
  def parse_prefix(<<201, 231, 2>> <> rest), do: {get(0xb3c9), rest}
  
  def parse_prefix(<<202, 231, 2>> <> rest), do: {get(0xb3ca), rest}
  
  def parse_prefix(<<203, 231, 2>> <> rest), do: {get(0xb3cb), rest}
  
  def parse_prefix(<<204, 231, 2>> <> rest), do: {get(0xb3cc), rest}
  
  def parse_prefix(<<205, 231, 2>> <> rest), do: {get(0xb3cd), rest}
  
  def parse_prefix(<<206, 231, 2>> <> rest), do: {get(0xb3ce), rest}
  
  def parse_prefix(<<207, 231, 2>> <> rest), do: {get(0xb3cf), rest}
  
  def parse_prefix(<<208, 231, 2>> <> rest), do: {get(0xb3d0), rest}
  
  def parse_prefix(<<209, 231, 2>> <> rest), do: {get(0xb3d1), rest}
  
  def parse_prefix(<<210, 231, 2>> <> rest), do: {get(0xb3d2), rest}
  
  def parse_prefix(<<211, 231, 2>> <> rest), do: {get(0xb3d3), rest}
  
  def parse_prefix(<<212, 231, 2>> <> rest), do: {get(0xb3d4), rest}
  
  def parse_prefix(<<213, 231, 2>> <> rest), do: {get(0xb3d5), rest}
  
  def parse_prefix(<<214, 231, 2>> <> rest), do: {get(0xb3d6), rest}
  
  def parse_prefix(<<215, 231, 2>> <> rest), do: {get(0xb3d7), rest}
  
  def parse_prefix(<<216, 231, 2>> <> rest), do: {get(0xb3d8), rest}
  
  def parse_prefix(<<217, 231, 2>> <> rest), do: {get(0xb3d9), rest}
  
  def parse_prefix(<<218, 231, 2>> <> rest), do: {get(0xb3da), rest}
  
  def parse_prefix(<<219, 231, 2>> <> rest), do: {get(0xb3db), rest}
  
  def parse_prefix(<<220, 231, 2>> <> rest), do: {get(0xb3dc), rest}
  
  def parse_prefix(<<221, 231, 2>> <> rest), do: {get(0xb3dd), rest}
  
  def parse_prefix(<<222, 231, 2>> <> rest), do: {get(0xb3de), rest}
  
  def parse_prefix(<<223, 231, 2>> <> rest), do: {get(0xb3df), rest}
  
  def parse_prefix(<<224, 231, 2>> <> rest), do: {get(0xb3e0), rest}
  
  def parse_prefix(<<225, 231, 2>> <> rest), do: {get(0xb3e1), rest}
  
  def parse_prefix(<<226, 231, 2>> <> rest), do: {get(0xb3e2), rest}
  
  def parse_prefix(<<227, 231, 2>> <> rest), do: {get(0xb3e3), rest}
  
  def parse_prefix(<<228, 231, 2>> <> rest), do: {get(0xb3e4), rest}
  
  def parse_prefix(<<129, 232, 2>> <> rest), do: {get(0xb401), rest}
  
  def parse_prefix(<<130, 232, 2>> <> rest), do: {get(0xb402), rest}
  
  def parse_prefix(<<131, 232, 2>> <> rest), do: {get(0xb403), rest}
  
  def parse_prefix(<<144, 178, 210, 5>> <> rest), do: {get(0xb49910), rest}
  
  def parse_prefix(<<129, 234, 2>> <> rest), do: {get(0xb501), rest}
  
  def parse_prefix(<<130, 234, 2>> <> rest), do: {get(0xb502), rest}
  
  def parse_prefix(<<144, 234, 2>> <> rest), do: {get(0xb510), rest}
  
  def parse_prefix(<<129, 236, 2>> <> rest), do: {get(0xb601), rest}
  
  def parse_prefix(<<192, 1>> <> rest), do: {get(0xc0), rest}
  
  def parse_prefix(<<193, 1>> <> rest), do: {get(0xc1), rest}
  
  def parse_prefix(<<202, 1>> <> rest), do: {get(0xca), rest}
  
  def parse_prefix(<<129, 152, 3>> <> rest), do: {get(0xcc01), rest}
  
  def parse_prefix(<<206, 1>> <> rest), do: {get(0xce), rest}
  
  def parse_prefix(<<145, 156, 3>> <> rest), do: {get(0xce11), rest}
  
  def parse_prefix(<<208, 1>> <> rest), do: {get(0xd0), rest}
  
  def parse_prefix(<<128, 160, 3>> <> rest), do: {get(0xd000), rest}
  
  def parse_prefix(<<141, 160, 3>> <> rest), do: {get(0xd00d), rest}
  
  def parse_prefix(<<128, 164, 192, 6>> <> rest), do: {get(0xd01200), rest}
  
  def parse_prefix(<<129, 164, 192, 6>> <> rest), do: {get(0xd01201), rest}
  
  def parse_prefix(<<130, 164, 192, 6>> <> rest), do: {get(0xd01202), rest}
  
  def parse_prefix(<<133, 164, 192, 6>> <> rest), do: {get(0xd01205), rest}
  
  def parse_prefix(<<128, 166, 192, 6>> <> rest), do: {get(0xd01300), rest}
  
  def parse_prefix(<<129, 166, 192, 6>> <> rest), do: {get(0xd01301), rest}
  
  def parse_prefix(<<130, 166, 192, 6>> <> rest), do: {get(0xd01302), rest}
  
  def parse_prefix(<<131, 166, 192, 6>> <> rest), do: {get(0xd01303), rest}
  
  def parse_prefix(<<132, 166, 192, 6>> <> rest), do: {get(0xd01304), rest}
  
  def parse_prefix(<<133, 166, 192, 6>> <> rest), do: {get(0xd01305), rest}
  
  def parse_prefix(<<134, 166, 192, 6>> <> rest), do: {get(0xd01306), rest}
  
  def parse_prefix(<<135, 166, 192, 6>> <> rest), do: {get(0xd01307), rest}
  
  def parse_prefix(<<136, 166, 192, 6>> <> rest), do: {get(0xd01308), rest}
  
  def parse_prefix(<<137, 166, 192, 6>> <> rest), do: {get(0xd01309), rest}
  
  def parse_prefix(<<138, 166, 192, 6>> <> rest), do: {get(0xd0130a), rest}
  
  def parse_prefix(<<139, 166, 192, 6>> <> rest), do: {get(0xd0130b), rest}
  
  def parse_prefix(<<128, 192, 192, 6>> <> rest), do: {get(0xd02000), rest}
  
  def parse_prefix(<<231, 161, 3>> <> rest), do: {get(0xd0e7), rest}
  
  def parse_prefix(<<234, 161, 3>> <> rest), do: {get(0xd0ea), rest}
  
  def parse_prefix(<<235, 161, 3>> <> rest), do: {get(0xd0eb), rest}
  
  def parse_prefix(<<237, 161, 3>> <> rest), do: {get(0xd0ed), rest}
  
  def parse_prefix(<<209, 1>> <> rest), do: {get(0xd1), rest}
  
  def parse_prefix(<<145, 163, 3>> <> rest), do: {get(0xd191), rest}
  
  def parse_prefix(<<212, 1>> <> rest), do: {get(0xd4), rest}
  
  def parse_prefix(<<213, 1>> <> rest), do: {get(0xd5), rest}
  
  def parse_prefix(<<224, 1>> <> rest), do: {get(0xe0), rest}
  
  def parse_prefix(<<225, 1>> <> rest), do: {get(0xe1), rest}
  
  def parse_prefix(<<226, 1>> <> rest), do: {get(0xe2), rest}
  
  def parse_prefix(<<227, 1>> <> rest), do: {get(0xe3), rest}
  
  def parse_prefix(<<228, 1>> <> rest), do: {get(0xe4), rest}
  
  def parse_prefix(<<229, 1>> <> rest), do: {get(0xe5), rest}
  
  def parse_prefix(<<230, 1>> <> rest), do: {get(0xe6), rest}
  
  def parse_prefix(<<231, 1>> <> rest), do: {get(0xe7), rest}
  
  def parse_prefix(<<232, 1>> <> rest), do: {get(0xe8), rest}
  
  def parse_prefix(<<234, 1>> <> rest), do: {get(0xea), rest}
  
  def parse_prefix(<<235, 1>> <> rest), do: {get(0xeb), rest}
  
  def parse_prefix(<<209, 214, 3>> <> rest), do: {get(0xeb51), rest}
  
  def parse_prefix(<<236, 1>> <> rest), do: {get(0xec), rest}
  
  def parse_prefix(<<237, 1>> <> rest), do: {get(0xed), rest}
  
  def parse_prefix(<<238, 1>> <> rest), do: {get(0xee), rest}
  
  def parse_prefix(<<239, 1>> <> rest), do: {get(0xef), rest}
  
  def parse_prefix(<<240, 1>> <> rest), do: {get(0xf0), rest}
  
  def parse_prefix(<<241, 1>> <> rest), do: {get(0xf1), rest}
  
  def parse_prefix(<<129, 226, 3>> <> rest), do: {get(0xf101), rest}
  
  def parse_prefix(<<130, 226, 3>> <> rest), do: {get(0xf102), rest}
  
  def parse_prefix(<<250, 1>> <> rest), do: {get(0xfa), rest}
  
  def parse_prefix(<<251, 1>> <> rest), do: {get(0xfb), rest}
  
  def parse_prefix(<<252, 1>> <> rest), do: {get(0xfc), rest}
  
  def parse_prefix(_), do: nil
end
