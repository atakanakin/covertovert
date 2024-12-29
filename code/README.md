
# Covert Channel Using NTP Reference Timestamp

## Overview
This project implements a covert channel using the NTP (Network Time Protocol) Reference Timestamp field. It encodes binary messages into the timestamp field of NTP packets, allowing covert transmission of data between sender and receiver. This demonstrates how covert channels can exploit legitimate protocols.

## Features
- Encodes and decodes binary data within NTP Reference Timestamp fields.
- Sends 16-character binary messages (128 bits) using custom encoding.
- Calculates and reports covert channel capacity in bits per second.
- Provides configurable parameters for testing and tuning the covert channel.

---

## Implementation Details

### Encoding and Decoding
1. **Encoding**:
   - A random 128-bit binary message is generated (16 characters long).
   - Each bit is encoded into the Reference Timestamp field of NTP packets.
2. **Decoding**:
   - The receiver extracts the encoded bits from incoming NTP packets.
   - The original message is reconstructed and logged.

### Message Transmission
- **Sender**: Generates and encodes a binary message, then transmits it as NTP packets.
- **Receiver**: Decodes received NTP packets to reconstruct the original message.

### Parameters and Configuration
- `parameter1`: Receiver's IP address or sniffing filter.
- `parameter2`: Maximum and minimum message length (set to 16 for this assignment).
- `log_file_name`: File where the original or decoded message is stored.

---

## Measuring Covert Channel Capacity

### Methodology
1. Generate a 16-character binary message (128 bits).
2. Start the timer just before sending the first packet.
3. Stop the timer after sending the last packet.
4. Calculate the time taken to send the message.
5. Compute the covert channel capacity using the formula:
   \[
   \text{Capacity (bits per second)} = \frac{128 \, \text{bits}}{\text{Time taken (seconds)}}
   \]

### Example Measurement
- **Time taken to send the message**: `0:00:03.162826`
- **Covert Channel Capacity**: 
  \[
  \text{Capacity} = \frac{128}{3.162826} \approx 40.47 \, \text{bps}
  \]

### Output
```plaintext
Time taken to send the message: 0:00:03.162826
Bits per second: 40.470136517152696
Sender is finished!
```

### Limitations
1. **Minimum and Maximum Message Length**:
   - Fixed to 128 bits (16 characters) for this assignment.
2. **Performance Factors**:
   - The covert channel capacity depends on network latency and packet processing times.
3. **Protocol Constraints**:
   - This implementation relies on NTP; disruptions to NTP packets could affect transmission.

---

## How to Run

### Prerequisites
- Python 3.x
- Required libraries: `scapy`, `datetime`, etc.

### Steps
1. **Sender**:
   ```bash
   python3 run.py send
   ```
2. **Receiver**:
   ```bash
   python3 run.py receive
   ```

### Example Output
- Sender log:
  ```plaintext
  Generated message: 1100101010110001
  Time taken to send the message: 0:00:03.162826
  Bits per second: 40.47
  ```
- Receiver log:
  ```plaintext
  Decoded message: 1100101010110001
  ```

---

## Documentation

The Sphinx-generated documentation is in the `docs/_build/html` folder. To view it:
   ```bash
   cd docs
   ```
2. Generate the documentation:
   ```bash
   make documentation
   ```
3. Open the `index.html` file in a browser:
   ```bash
   open _build/html/index.html  # macOS
   xdg-open _build/html/index.html  # Linux
   start _build/html/index.html  # Windows
   ```

---

## Authors
- **Ali Atakan Akın** (2448058)
- **Tahsin Elmas** (2476844)

## Group ID
- **17**

## Repository Link
- [GitHub Repository](https://github.com/atakanakin/covertovert/tree/phase2)

