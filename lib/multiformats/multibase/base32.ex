defmodule Multiformats.Multibase.Base32 do
  @moduledoc """
  Delegates to Elixir's `Base` module.

  This module and its functions exist solely to provide a consistent interface for encoding and decoding data using the `Multibase` library.
  """

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  See `Base.encode32/2`.
  """
  defdelegate encode(data, opts \\ []), to: Base, as: :encode32

  @doc """
  See `Base.decode32/2`.
  """
  defdelegate decode(data, opts \\ []), to: Base, as: :decode32

  @doc """
  See `Base.decode32!/2`.
  """
  defdelegate decode!(data, opts \\ []), to: Base, as: :decode32!
end

defmodule Multiformats.Multibase.Base32Hex do
  @moduledoc """
  Delegates to Elixir's `Base` module.

  This module and its functions exist solely to provide a consistent interface for encoding and decoding data using the `Multibase` library.
  """

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  See `Base.hex_encode32/2`.
  """
  defdelegate encode(data, opts \\ []), to: Base, as: :hex_encode32

  @doc """
  See `Base.hex_decode32/2`.
  """
  defdelegate decode(data, opts \\ []), to: Base, as: :hex_decode32

  @doc """
  See `Base.hex_decode32!/2`.
  """
  defdelegate decode!(data, opts \\ []), to: Base, as: :hex_decode32!
end
