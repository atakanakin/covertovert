import random
import string
from datetime import datetime


def generate_random_char():
    """Generate random printable ASCII character"""
    return random.choice(string.printable)


def encode_bit_into_timestamp(timestamp, bit):
    # return 0 | bit
    """
    Encode bit using random char in timestamp
    Format: [...23 bits...][8 bits char][1 bit data]
    """
    # Generate random char and get its ASCII value
    random_char = generate_random_char()
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


def decode_bit_from_timestamp(timestamp):
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


a = 0

while True:
    bit = a % 2
    timestamp = int(datetime.now().timestamp())
    encoded_timestamp = encode_bit_into_timestamp(timestamp, bit)
    decoded_bit = decode_bit_from_timestamp(encoded_timestamp)
    assert bit == decoded_bit
    a += 1
