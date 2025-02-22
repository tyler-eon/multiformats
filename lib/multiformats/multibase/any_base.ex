defmodule Multiformats.Multibase.AnyBase do
  @moduledoc """
  This module can be used to create custom "any base" encoding/decoding functions.

  The module creates code similar to Elixir's own `Base` module, except each module is intended to encapsulate a single base rather than multiple ones.

  A custom alphabet must be provided, and that alphabet is used to generate encoding and decoding functions at compile time.

  By default, the "base" of the module is determined by the number of characters in the provided alphabet, e.g. `Base58` has a base of 58 because there are 58 characters.

  At this time, padding is not an available option when using this module.

  *Note*: This module is not intended to be able to recreate _any_ multibase codec. The specific logic assumed by the generated code to encode and decode the data might not be applicable to all codecs. Ensure you thoroughly test any custom multibase codecs derived from this module.

  ## Examples

  Let's say you wanted to have a base 58 "codec":

      defmodule Base58 do
        use Multiformats.Multibase.AnyBase
          name: :base58btc,
          alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      end

  Then you can invoke the custom base codec using `encode/1` and `decode/1`:

      Base58.encode("it's multiformats!")
      # => "5NgpeksG5ZXZxPmAGtXZq7a7r"

      Base58.decode("5NgpeksG5ZXZxPmAGtXZq7a7r")
      # => {:ok, "it's multiformats!"}

  Additionally, there are overridable "hook" functions that allow custom modules to have more control over the encoding and decoding algorithms. These functions are executed _at runtime_, not during compilation.

  - `before_encode/1`
  - `after_encode/1`
  - `before_decode/1`
  - `after_decode/1`

  Because the encoding and decoding algorithms assume that binary strings are the inputs and outputs, each hook function should expect a binary string input and return a binary string output.
  """

  defmacro __using__(opts) do
    name = Keyword.fetch!(opts, :name)
    alphabet = Keyword.fetch!(opts, :alphabet)
    base = String.length(alphabet)

    encode_fn = :"encode_#{name}"
    encode_char_fn = :"encode_char_#{name}"
    encode_prefix_fn = :"encode_prefix_#{name}"

    decode_fn = :"decode_#{name}"
    decode_char_fn = :"decode_char_#{name}"
    decode_prefix_fn = :"decode_prefix_#{name}"

    alphalist = String.to_charlist(alphabet)

    char_encoders =
      for {char, n} <- Enum.with_index(alphalist) do
        quote do
          defp unquote(encode_char_fn)(unquote(n)), do: unquote(char)
        end
      end

    char_decoders =
      for {char, n} <- Enum.with_index(alphalist) do
        quote do
          defp unquote(decode_char_fn)(unquote(char)), do: unquote(n)
        end
      end

    zero_char = Enum.at(alphalist, 0)

    quote do
      # "Hook" functions to allow more control over the encoding and decoding algorithms.
      def before_encode(input) when is_binary(input), do: input
      def after_encode(input) when is_binary(input), do: input
      def before_decode(input) when is_binary(input), do: input
      def after_decode(input) when is_binary(input), do: input
      defoverridable([before_encode: 1, after_encode: 1, before_decode: 1, after_decode: 1])

      unquote(char_encoders)

      def encode(input, _opts \\ []) when is_binary(input) do
        input
        |> :binary.decode_unsigned()
        |> unquote(encode_fn)([])
        |> unquote(encode_prefix_fn)(input)
        |> to_string()
      end

      defp unquote(encode_fn)(0, acc), do: acc

      defp unquote(encode_fn)(n, acc) do
        quotient = div(n, unquote(base))
        char = rem(n, unquote(base)) |> unquote(encode_char_fn)()
        unquote(encode_fn)(quotient, [char | acc])
      end

      defp unquote(encode_prefix_fn)(acc, << 0, rest :: binary>>) do
        unquote(encode_prefix_fn)([unquote(encode_char_fn)(0) | acc], rest)
      end

      defp unquote(encode_prefix_fn)(acc, _), do: acc

      unquote(char_decoders)

      def decode(input, opts \\ []) when is_binary(input) do
        {:ok, decode!(input, opts)}
      rescue
        error ->
          {:error, error}
      end

      def decode!(input, _opts \\ []) when is_binary(input) do
        {remaining, zero_count} = unquote(decode_prefix_fn)(input, 0)
        body = unquote(decode_fn)(remaining, 0) |> :binary.encode_unsigned()
        << 0 :: size(zero_count) - unit(8), body :: binary >>
      end

      defp unquote(decode_fn)([], acc), do: acc

      defp unquote(decode_fn)([char | rest], acc) do
        unquote(decode_fn)(rest, acc * unquote(base) + unquote(decode_char_fn)(char))
      end

      defp unquote(decode_prefix_fn)(<< unquote(zero_char), rest :: binary>>, count) do
        unquote(decode_prefix_fn)(rest, count + 1)
      end

      defp unquote(decode_prefix_fn)(rest, count), do: {String.to_charlist(rest), count}
    end
  end
end
