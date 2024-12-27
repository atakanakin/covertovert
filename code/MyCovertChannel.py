from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, Raw
import struct
from scapy.layers.ntp import NTPHeader  # Ensure the NTP layer is imported
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
        message_length = len(binary_message)
        print(f"Generated message: {message_length} characters long.")
        binary_count_str = (bin(message_length)[2:]).zfill(32)
        
        print(f"Generated binary message: {binary_message}")
        temp_payload = binary_count_str + binary_message

        for i, bit in enumerate(temp_payload):
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
            print(f"Sent packet {i + 1}/{len(temp_payload)} with encoded bit: {bit}")

   

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - Receives NTP packets, decodes the Reference Timestamp field, and reconstructs the message.
        :param parameter1: Filter for sniffing packets (e.g., "udp port 123").
        :param parameter2: Number of packets to capture.
        :param parameter3: Not used in this implementation.
        :param log_file_name: File name to log the decoded message.
        """
        from scapy.all import sniff

        print("Listening for packets...")
        packets_length = sniff(filter=parameter1, count=32)
        packet_count = int(self.receive_extract(packets_length), 2)
        print(f"Expecting {packet_count} packets.")


        packets = sniff(filter=parameter1, count=packet_count)

        decoded_message = self.receive_extract(packets)
        final_message = ""
        # Log the decoded message
        for i in range(0, len(decoded_message), 8):
            decoded_char = self.convert_eight_bits_to_character(decoded_message[i:i+8])
            final_message += decoded_char
        self.log_message(final_message, log_file_name)
        print(f"Decoded message logged to {log_file_name}.")

    def receive_extract(self, packets):
        """
        - Extracts the Reference Timestamp field from an NTP packet.
        :param packet: NTP packet to extract the Reference Timestamp.
        :return: Extracted Reference Timestamp.
        """
        decoded_message = ""
        for i, packet in enumerate(packets):
            # print(f"Packet {i + 1}: {packet.summary()}")  # Debug packet summary
            if packet.haslayer(NTPHeader):
                ntp_layer = packet[NTPHeader]
                ref_timestamp = int(ntp_layer.ref * (2**32))  # Extract and scale the Reference Timestamp
                bit = self.decode_bit_from_timestamp(ref_timestamp)
                decoded_message += str(bit)
                print(f"Decoded bit {i + 1}/{len(packets)}: {bit}")
            else:
                print(f"Packet {i + 1} does not contain an NTPHeader layer.")
        return decoded_message