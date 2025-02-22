# multiformats

This is an Elixir implementation of the [multiformats](https://github.com/multiformats/multiformats) set of specifications.

*Note*: This library is still under construction. While it should work in most common use cases, there still may be some bugs or missing pieces. The only real use this has seen is for encoding and decoding CIDs for the AT Protocol. Beyond that, there isn't a lot of testing yet. You have been warned.

## Don't these already exist?

There are other, older implementations of the various components of the multiformats umbrella, but many of them haven't been updated in years and don't necessarily work with the latest versions of Elixir.

Many of them also either used code generation that wasn't included as part of the source library or were created by hand, which would make updating the components difficult without the original maintainer's help.

The goal of this library was twofold:

1. Provide an updated implementation that works with the latest versions of Elixir/Erlang.
2. Use code generation as much as possible to make the library more maintainable and easier to update if specifications or the underlying source tables change.

While the underlying implementations of the various codecs *cannot* be generated, the metadata about them *can be*. Specifically, the ability to encode and decode the various multiformats components is a great candidate for code generation. By using [this source table](https://github.com/multiformats/multicodec/blob/master/table.csv), we can generate the metadata for the various multiformats components as well as use function matching to provide efficient parsing during decoding.

## Supported Components

The following multiformats components are currently supported by this library:

- [multibase](https://github.com/multiformats/multibase)
- [multicodec](https://github.com/multiformats/multicodec)
- [multihash](https://github.com/multiformats/multihash)

While the multicodec module might still be capable of identifying other multiformats components, such as `multiaddr` binary data based on a particular prefix, this library currently cannot do anything specific with the data associated with those other components.

## Custom Codecs

Right now, this library only uses the codecs it maintains, meaning it is not yet possible to bring custom codecs into your application and have them work seamlessly with this library; even if they are specified in the multicodec source table.

However, there *is* a plan to support custom codecs eventually. That is why `Multiformats.Multicodec.Codec` exists: to provide a unified interface for all codecs to use. All codecs implemented by the `multibase` and `multihash` components in this library implement this behaviour. Eventually, other modules outside of this library will be able to implement this behaviour as well and then "register" themselves with `Multiformats.Multicodec`.

Thankfully, there's really only one component that makes direct use of the codecs: `Multiformats.CID`. This means that even as of now, you can pretty much use whatever codecs you want with the remainder of the library. `Multiformats.Multicodec` will simply give you the codec metadata and binary data during a `decode/1` operation; it's up to you to decide what to do with that information. Same with the `encode/2` function: it assumes the underlying binary data is already encoded using whatever codec you want, and all it does it prefix the binary data with the appropriate prefix.

TL;DR: While the CID stuff only works with the codecs maintained by this library, you can use custom codecs in your own applications otherwise.

## CIDs

With the rise of the AT Protocol (at the time of writing this), CIDs are perhaps one of the most fundamental uses of multiformats. CIDs are instrumental not just as unique identifiers for block storage (e.g. a key-value database), but also used within the PDS (Personal Data Store) as links between "nodes" within the MST (Merkle Search Tree). And while most applications using AT Protocol won't actually need to encode or decode CIDs, it is still a useful concept to understand and this library provides support for these operations through the `CID` module.

You can read about the details of the CID specification [here](https://github.com/multiformats/cid). TL;DR: CIDs are effectively a two-element tuple of `(content type, content address)`, where the content address is a multihash of the content itself.  And because CIDs are intended to be passed around as text, they are multibase encoded to ensure they can be stored and transmitted using a variety of common methods, e.g. within a URL.

### v0 and v1

Both v0 and v1 CIDs are supported, although it is recommended to use CIDv1 instead of CIDv0. CIDv0 is *NOT* self-describing, although it does still make use of some of the codecs seen within the multiformats umbrella. But the biggest drawback is that, because it is not self-describing, the hashing algorithm, content type, and multibase encoding are locked to specific values and cannot be changed. CIDv1 allows for all of these values to be whatever is supported by multiformats as a whole as the entire CID value is self-describing.

For CIDv0, the structure is:

```
<multihash-content-address>
```

And that's it. It's just a multihash output of the content, which *always* uses the `sha2-256` hashing algorithm. CIDv0 binary strings are also *always* `base58btc` encoded (but without the `z` prefix) and the multicodec type is *always* `dag-pb` (again, without the `p` prefix).

If your content isn't `dag-pb` encoded, or you want to use a different hashing algorithm, or you don't want to use `base58btc` encoding, then you *MUST* use CIDv1.

For CIDv1, the structure is:

```
<version><multicodec><multihash>
```

Or more detailed:
```
<0x01><multicodec prefix of the content type><multihash output of the addressed content>
```

In addition to the content address (which is a multihash of the content), we also have the content type as a multicodec prefix. And we see the whole thing is prefixed by `0x01` to indicate the CID version is 1. And, as mentioned earlier, CIDs are multibase encoded as well. The above structure is the multibase *decoded* structure of a CID.

### Encoding and Decoding

Encoding for v1:

1. Generate a multihash of the content.
2. Prefix the result with the multicodec prefix for the content type.
3. Prefix the result with the CID version number (in the case of v1, this is `0x01`).
4. Encode the result with a multibase of your choice.

Decoding for v1 is just the reverse of the above. For v0 there's only one step, which is the multihash part.


### Example

Although this library provides a `CID` module which can do the encoding and decoding for you, this example will walk through the individual steps of the decoding process to illustrate how a CID is composed.

Let's take an example CID and decode it: [zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA](https://cid.ipfs.tech/#zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA).

```elixir
# The CID is multibase encoded, so let's decode it first.
decoded_cid = Multibase.decode!("zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA")

# Since cidv1 is a multicodec type, we can use our multicodec compendium to decode it.
{:ok, {"cidv1", content_data}} = Multicodec.decode(decoded_cid)

# The content data is also multicodec encoded, so let's run that decode step again.
{:ok, {content_type, content_address}} = Multicodec.decode(content_data)

# The content address is a multihash of the content, so let's decode that as well.
{algo, size, digest} = Multihash.decode(content_address)

# It's also possible to multibase encode the digest part.
# This might be helpful if you want to shorten logging or other output locations of the digest.
{_, _, encoded_digest} = Multihash.decode(content_address, base: :base58btc)
```

To do the same thing using the `CID` module:

```elixir
%CID{} = CID.decode("zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA")
```

The `CID` struct encapsulates all of the information that we got from the above step-by-step process, including the original CID string.

While you could do the step-by-step process above but in reverse, the `CID` module provides an `encode/2` function that does it all for you, and also comes with default codecs for each step that you may freely override.

```elixir
"zb2rhe5P4gXftAwvA4eXQ5HJwsER2owDyS9sKaQRRVQPn93bA" = CID.encode(content_data, base: :base58btc)
```

Just remember: your `content_data` must be a binary and it must be in the same format as expressed by the `content_type` specified. If no `content_type` is specified, the default is `raw`, which means there is no modification of the content from its original binary form (typically this is a just a blob of binary data).
