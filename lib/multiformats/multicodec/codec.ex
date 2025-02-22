defmodule Multiformats.Multicodec.Codec do
  @moduledoc """
  A behaviour that defines common operations for "codecs" within the multiformats ecosystem.

  At a high-level, a "codec" is simply an encapsulation of two functions: encoding and decoding. Both functions accept binary data and return binary data.

  In order to support maximum flexibility, all functions accepts a second argument that can be anything. If you want to avoid having to manually write the 1-arity version of these functions by hand, you can `use` this module to have those functions generated for you. They will simply pass along an empty list (`[]`) to the 2-arity functions defined by this behaviour.

  *Note*: The `multihash` codecs are unique in that they are one-way cryptographic functions, meaning there is not way to reasonably "decode" the contents of a multihash. Therefore, it is encouraged to have `decode/2` and `decode!/2` raise errors when called from a `multihash` codec.
  """

  @doc """
  Encodes binary data with a set of optional arguments.
  """
  @callback encode(binary(), any()) :: binary()

  @doc """
  Decodes binary data, returning `{:ok, binary()}` if successful or `{:error, atom()}` if not.
  """
  @callback decode(binary(), any()) :: {:ok, binary()} | {:error, atom()}

  @doc """
  Decodes binary data, raising an error if the decoding fails.
  """
  @callback decode!(binary(), any()) :: binary()

  @doc """
  Adds the `@behaviour` attribute to the module and generates the 1-arity versions of the functions, which just call the 2-arity versions with an empty list for the second argument.

  You may optionally pass in `multihash: true` in the options argument to have `decode/2` and `decode!/2` stubs generated in the resulting code, with each one simply raising a runtime error. This is `false` by default, i.e. it is assumed this is not a `multihash` codec.
  """
  defmacro __using__(opts) do
    multihash = Keyword.get(opts, :multihash, false)

    quote do
      @behaviour Multiformats.Multicodec.Codec

      @doc """
      Encodes binary data using the default set of options.
      """
      def encode(data), do: encode(data, [])

      @doc """
      Decodes binary data using the default set of options.
      """
      def decode(data), do: decode(data, [])

      @doc """
      Decodes binary data using the default set of options, raising an error if the decoding fails.
      """
      def decode!(data), do: decode!(data, [])

      if unquote(multihash) do
        @doc """
        Not implemented.
        """
        def decode(_data, _opts), do: raise("Multihash codecs do not support decoding.")

        @doc """
        Not implemented.
        """
        def decode!(_data, _opts), do: raise("Multihash codecs do not support decoding.")
      end
    end
  end
end
