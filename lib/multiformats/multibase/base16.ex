defmodule Multiformats.Multibase.Base16 do
  @moduledoc """
  Delegates to Elixir's `Base` module.

  This module and its functions exist solely to provide a consistent interface for encoding and decoding data using the `Multibase` library.
  """

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  See `Base.encode16/2`.
  """
  defdelegate encode(data, opts \\ []), to: Base, as: :encode16

  @doc """
  See `Base.decode16/2`.
  """
  defdelegate decode(data, opts \\ []), to: Base, as: :decode16

  @doc """
  See `Base.decode16!/2`.
  """
  defdelegate decode!(data, opts \\ []), to: Base, as: :decode16!
end
