defmodule BinaryKata do

  @utf8_bom <<0xEF, 0xBB, 0xBF>>
  @jpeg_magic_numbers <<0xFF, 0xD8, 0xFF>>
  @png_magic_numbers <<0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A>>
  @gif_magic_numbers1 <<0x47, 0x49, 0x46, 0x38, 0x37, 0x61>>
  @gif_magic_numbers2 <<0x47, 0x49, 0x46, 0x38, 0x39, 0x61>>

  @doc """
  Should return `true` when given parameter start with UTF8 Byte-Order-Mark, otherwise `false`.
  @see https://en.wikipedia.org/wiki/Byte_order_mark
  """
  def has_utf8_bom?(<<bom::binary-size(3), _::binary>>) when bom == @utf8_bom, do: true
  def has_utf8_bom?(_), do: false

  @doc """
  Remove a UTF8 BOM if exists.
  """
  def remove_utf8_bom(binary) do
    case has_utf8_bom?(binary) do
      true ->
        <<_::binary-size(3), without_utf8_bom::binary>> = binary
        without_utf8_bom

      false ->
        binary
    end
  end

  @doc """
  Add a UTF8 BOM if not exists.
  """
  def add_utf8_bom(binary) do
    case has_utf8_bom?(binary) do
      true ->
        binary

      false ->
        @utf8_bom <> binary
    end
  end

  @doc """
  Detecting types of images by their first bytes / magic numbers.

  @see https://en.wikipedia.org/wiki/JPEG
  @see https://en.wikipedia.org/wiki/Portable_Network_Graphics
  @see https://en.wikipedia.org/wiki/GIF
  """
  def image_type!(<<magic::binary-size(3), _::binary>>) when magic == @jpeg_magic_numbers, do: :jfif
  def image_type!(<<magic::binary-size(8), _::binary>>) when magic == @png_magic_numbers,  do: :png
  def image_type!(<<magic::binary-size(6), _::binary>>) when magic == @gif_magic_numbers1, do: :gif
  def image_type!(<<magic::binary-size(6), _::binary>>) when magic == @gif_magic_numbers2, do: :gif
  def image_type!(_), do: :unknown

  @doc """
  Get the width and height from a GIF image.
  First 6 bytes contain the magic header.

  `width` will be little-endian in byte 7 and 8.
  `height` will be little-endian in byte 9 and 10.
  """
  def gif_dimensions!(_), do: raise "TODO: Implement me!"

  @doc """
  Parsing Payload of a ARP packet. Padding will be omitted.

  @see https://en.wikipedia.org/wiki/Address_Resolution_Protocol
  """
  def parse_arp_packet_ipv4!(_) do
      raise "TODO: Implement me!"
  end

  # Helper for `parse_arp_packet_ipv4!`
  defp arp_operation_to_atom(1), do: :request
  defp arp_operation_to_atom(2), do: :response

end
