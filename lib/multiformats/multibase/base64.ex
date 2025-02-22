defmodule Multiformats.Multibase.Base64 do
  @moduledoc """
  Delegates to Elixir's `Base` module.

  This module and its functions exist solely to provide a consistent interface for encoding and decoding data using the `Multibase` library.
  """

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  See `Base.encode64/2`.
  """
  defdelegate encode(data, opts \\ []), to: Base, as: :encode64

  @doc """
  See `Base.decode64/2`.
  """
  defdelegate decode(data, opts \\ []), to: Base, as: :decode64

  @doc """
  See `Base.decode64!/2`.
  """
  defdelegate decode!(data, opts \\ []), to: Base, as: :decode64!
end

defmodule Multiformats.Multibase.Base64URL do
  @moduledoc """
  Delegates to Elixir's `Base` module.

  This module and its functions exist solely to provide a consistent interface for encoding and decoding data using the `Multibase` library.
  """

  @behaviour Multiformats.Multicodec.Codec

  @doc """
  See `Base.url_encode64/2`.
  """
  defdelegate encode(data, opts \\ []), to: Base, as: :url_encode64

  @doc """
  See `Base.url_decode64/2`.
  """
  defdelegate decode(data, opts \\ []), to: Base, as: :url_decode64

  @doc """
  See `Base.url_decode64!/2`.
  """
  defdelegate decode!(data, opts \\ []), to: Base, as: :url_decode64
end
