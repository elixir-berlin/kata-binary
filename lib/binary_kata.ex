defmodule BinaryKata do

  @doc """
  Should return `true` when given parameter start with UTF8 Byte-Order-Mark, otherwise `false`.
  @see https://en.wikipedia.org/wiki/Byte_order_mark
  """
  def has_utf8_bom?(<<0xEF,0xBB,0xBF,_::binary>>), do: true
  def has_utf8_bom?(_), do: false

  @doc """
  Remove a UTF8 BOM if exists.
  """
  def remove_utf8_bom(<<0xEF,0xBB,0xBF,rest::binary>>), do: rest
  def remove_utf8_bom(<<rest::binary>>), do: rest

  @doc """
  Add a UTF8 BOM if not exists.
  """
  def add_utf8_bom(all = <<0xEF,0xBB,0xBF,_::binary>>), do: all
  def add_utf8_bom(all), do: <<0xEF,0xBB,0xBF>> <> all

  @doc """
  Detecting types of images by their first bytes / magic numbers.

  @see https://en.wikipedia.org/wiki/JPEG
  @see https://en.wikipedia.org/wiki/Portable_Network_Graphics
  @see https://en.wikipedia.org/wiki/GIF
  """
  def image_type!("GIF" <> _), do: :gif
  def image_type!(<<_::binary-size(6),"JFIF", _::binary>>), do: :jfif
  def image_type!(<<_::binary-size(1),"PNG", _::binary>>), do: :png
  def image_type!(_), do: :unknown

  @doc """
  Get the width and height from a GIF image.
  First 6 bytes contain the magic header.

  `width` will be little-endian in byte 7 and 8.
  `height` will be little-endian in byte 9 and 10.
  """
  # def gif_dimensions!(<<_::binary-size(6), width::little-integer-size(2), height::little-integer-size(2), _::binary>>) do
  #   {width, height}
  # end
  def gif_dimensions!(<<"GIF", _::binary-size(3), width::little-integer-size(16), height::little-integer-size(16), _::binary>>) do
    {width, height}
  end
  def gif_dimensions!(_), do: :error
  @doc """
  Parsing Payload of a ARP packet. Padding will be omitted.

  @see https://en.wikipedia.org/wiki/Address_Resolution_Protocol
  """
  def parse_arp_packet_ipv4!(<<_::binary-size(7), op::integer-size(8), sha::integer-size(48), spa::binary-size(4), tha::integer-size(48), tpa::binary-size(4), _::binary>>) do
      <<a, b, c, d>> = spa
      <<e, f, g, h>> = tpa
      {arp_operation_to_atom(op), sha, {a, b, c, d}, tha, {e, f, g, h}}
  end

  # Helper for `parse_arp_packet_ipv4!`
  defp arp_operation_to_atom(1), do: :request
  defp arp_operation_to_atom(2), do: :response

end
