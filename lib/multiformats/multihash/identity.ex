defmodule Multiformats.Multihash.Identity do
  @moduledoc """
  The "identity" multihash algorithm is a no-op, meaning "do not hash the binary data."
  """

  use Multiformats.Multicodec.Codec, multihash: true

  @doc """
  Returns the data unchanged.
  """
  @impl true
  def encode(data, _), do: data
end
