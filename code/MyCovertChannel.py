from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, Raw, sniff
import struct
from scapy.layers.ntp import NTPHeader


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

    def encode_bit_into_timestamp(self, timestamp, bit):
        """
        Encodes a single bit into the least significant bit of the Reference Timestamp.
        :param timestamp: Original timestamp (integer).
        :param bit: Bit to encode (0 or 1).
        :return: Modified timestamp with encoded bit.
        """
        return (timestamp & ~1) | int(bit)

    def decode_bit_from_timestamp(self, timestamp):
        """
        Decodes a single bit from the least significant bit of the Reference Timestamp.
        :param timestamp: Modified timestamp (integer).
        :return: Decoded bit (0 or 1).
        """
        return timestamp & 1

    def send(self, log_file_name, parameter1, parameter2):
        """
        - Generates a binary message, encodes it into NTP packets, and sends them to the receiver.
        :param log_file_name: File name to log the original message.
        :param parameter1: Receiver container's IP address.
        :param parameter2: Number of packets to send.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,  max_length=parameter2)
        
        print(f"Generated binary message: {binary_message}")

        for i, bit in enumerate(binary_message):
            # Create IP and UDP headers
            ip_layer = IP(dst=parameter1)
            udp_layer = UDP(sport=123, dport=123)

            # Construct NTP payload (48 bytes) with a custom Reference Timestamp
            ntp_payload = bytearray(48)
            ref_timestamp = self.encode_bit_into_timestamp(0, bit)  # Encode the bit into timestamp
            struct.pack_into('!Q', ntp_payload, 16, ref_timestamp)  # Pack timestamp at offset 16

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
                ref_timestamp = int(ntp_layer.ref * (2**32))  # Extract and scale the Reference Timestamp
                bit = self.decode_bit_from_timestamp(ref_timestamp)
                decoded_message.append(str(bit))
                print(f"Decoded bit: {bit}")
                
                # Check if we have received 8 bits to form a character
                if len(decoded_message) % 8 == 0:
                    # Decode the last 8 bits into a character
                    char = self.convert_eight_bits_to_character("".join(decoded_message[-8:]))
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
            final_message += self.convert_eight_bits_to_character("".join(decoded_message[i:i+8]))

        # Log the decoded message
        self.log_message(final_message, log_file_name)
        print(f"Decoded message logged to {log_file_name}.")
