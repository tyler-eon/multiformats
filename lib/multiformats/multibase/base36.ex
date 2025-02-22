defmodule Multiformats.Multibase.Base36 do
  use Multiformats.Multibase.AnyBase,
    name: :base36,
    alphabet: "0123456789abcdefghijklmnopqrstuvwxyz"

  @behaviour Multiformats.Multicodec.Codec
end
