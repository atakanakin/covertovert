from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, Raw, sniff
import struct
from scapy.layers.ntp import NTPHeader
from datetime import datetime
from time import sleep
import random
import string


class StopSniffingException(Exception):
    pass


class MyCovertChannel(CovertChannelBase):
    """
    - Implements a covert channel using NTP protocol's Reference Timestamp field.
    """

    def __init__(self):
        """
        - Initialize additional attributes if needed.
        """
        super().__init__()

    def generate_random_char(self):
        """Generate random printable ASCII character"""
        return random.choice(string.printable)

    def encode_bit_into_timestamp(self, timestamp, bit):
        # return 0 | bit
        """
        Encode bit using random char in timestamp
        Format: [...23 bits...][8 bits char][1 bit data]
        """
        # Generate random char and get its ASCII value
        random_char = self.generate_random_char()
        char_value = ord(random_char)

        # Clear last 9 bits of timestamp and shift left
        timestamp = (timestamp >> 9) << 9

        # Insert char value in bits 1-8
        timestamp |= char_value << 1

        # Decide flip based on 1's count in char
        ones_count = bin(char_value).count("1")
        should_flip = (ones_count % 2) == 1

        # Apply encoding
        final_bit = (1 - bit) if should_flip else bit

        # Set final bit
        return timestamp | final_bit

    def decode_bit_from_timestamp(self, timestamp):
        # return timestamp & 1
        """
        Decode bit using char from timestamp
        """
        # Extract char value (bits 1-8)
        char_value = (timestamp >> 1) & 0xFF
        # Get encoded bit (last bit)
        encoded_bit = timestamp & 1

        # Determine flip based on char's 1's count
        ones_count = bin(char_value).count("1")
        should_flip = (ones_count % 2) == 1

        # Return original bit
        return (1 - encoded_bit) if should_flip else encoded_bit

    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a binary message, encodes it into NTP packets, and sends them to the receiver.
        :param log_file_name: File name to log the original message.
        :param parameter1: Receiver container's IP address.
        :param parameter2: Random message max length.
        """
        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name, max_length=parameter2
        )

        print(f"Generated binary message: {binary_message}")

        for i, bit in enumerate(binary_message):
            # Create IP and UDP headers
            ip_layer = IP(dst=parameter1)
            udp_layer = UDP(sport=123, dport=123)

            # Construct NTP payload (48 bytes) with a custom Reference Timestamp
            ntp_payload = bytearray(48)
            current_timestamp = int(datetime.now().timestamp())
            ref_timestamp = self.encode_bit_into_timestamp(
                current_timestamp, int(bit)
            )  # Encode the bit into timestamp
            struct.pack_into(
                "!Q", ntp_payload, 16, ref_timestamp
            )  # Pack timestamp at offset 16

            # Create the packet and send it
            packet = ip_layer / udp_layer / Raw(load=bytes(ntp_payload))
            super().send(packet)
            print(f"Sent packet {i + 1}/{len(binary_message)} with encoded bit: {bit}")

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Receives NTP packets, decodes the Reference Timestamp field, and reconstructs the message.
        :param parameter1: Filter for sniffing packets (e.g., "udp port 123").
        :param parameter2: Not used for fixed packet count in this implementation.
        :param parameter3: Not used in this implementation.
        :param log_file_name: File name to log the decoded message.
        """
        decoded_message = []

        def packet_handler(packet):
            """
            Processes each packet, decodes its bit, and checks for the stop condition.
            """
            if packet.haslayer(NTPHeader):
                ntp_layer = packet[NTPHeader]
                ref_timestamp = struct.unpack_from("!Q", bytes(ntp_layer), 16)[
                    0
                ]  # Unpack timestamp from offset 16
                bit = self.decode_bit_from_timestamp(int(ref_timestamp))
                decoded_message.append(str(bit))
                print(f"Decoded bit: {bit}")

                # Check if we have received 8 bits to form a character
                if len(decoded_message) % 8 == 0:
                    # Decode the last 8 bits into a character
                    char = self.convert_eight_bits_to_character(
                        "".join(decoded_message[-8:])
                    )
                    print(f"Decoded character: {char}")
                    if char == ".":
                        raise StopSniffingException()  # Stop sniffing when the end marker is detected

        try:
            print("Listening for packets...")
            sniff(filter=parameter1, prn=packet_handler)
        except StopSniffingException:
            print("End marker received. Stopping sniffing.")

        # Combine the decoded message into characters
        final_message = ""
        for i in range(0, len(decoded_message), 8):
            final_message += self.convert_eight_bits_to_character(
                "".join(decoded_message[i : i + 8])
            )

        # Log the decoded message
        self.log_message(final_message, log_file_name)
        print(f"Decoded message logged to {log_file_name}.")
