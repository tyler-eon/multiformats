defmodule Multiformats.Multibase.Base58 do
  use Multiformats.Multibase.AnyBase,
    name: :base58,
    alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

  @behaviour Multiformats.Multicodec.Codec
end

defmodule Multiformats.Multibase.Base58Flickr do
  use Multiformats.Multibase.AnyBase,
    name: :base58flickr,
    alphabet: "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ"

  @behaviour Multiformats.Multicodec.Codec
end

defmodule Multiformats.Multibase.Base58Ripple do
  use Multiformats.Multibase.AnyBase,
    name: :base58ripple,
    alphabet: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"

  @behaviour Multiformats.Multicodec.Codec
end
