import argparse
import serial
import sys
import time
import re


#Mazda Key
Default_KEY  = "4d 61 7a 64 41" # MazdA


BAUD_RATE = 38400
TIMEOUT = 0.01
ROMFILE = "rom.bin"
TMPFILE = "dump_progress.log"

 
def parse_file(file_path):
    with open(file_path, 'r') as file:
        data = file.readlines()

    # responses = []
    responses = ""
    for line in data:
        if "Response:" in line:
            response_str = line.split("Response:")[1].strip()
            response = re.findall(r"'([^']*)'", response_str)
            response = response[2:]
            response = response[:-2]
            response = [item.split(":", 1)[1] for item in response]
            # responses.append(response)
            hex_str = "".join(response)
            assert hex_str[:2] == "63"
            hex_str = hex_str[2:]
            assert all([hex_char == '0' for hex_char in hex_str[2048:]])
            hex_str = hex_str[:2048]
            responses += "".join(hex_str)

    return responses

def write_hex_str_to_binary(hex_str, outfile):
    byte_data = bytes.fromhex(hex_str)
    with open(outfile, 'wb') as file:
        file.write(byte_data)


def dump_rom(port, baud, secret, outfile):
    try:
        ser = serial.Serial(port, BAUD_RATE, timeout=TIMEOUT)
 
        # Avoid https://github.com/pyserial/pyserial/issues/735
        time.sleep(5)
    except serial.SerialException as e:
        print("ERROR: Could not open COM port '{}'".format(port))
        print(e)
        #import pdb; pdb.set_trace()
        sys.exit()
 
    print("Mazda ROM dumper")
    print(f"Connecting with {port}...")
    recognized = False
    ser.timeout = 0.3
    if not baud:
        tryRates = [38400, 57600, 115200, 230400, 460800, 500000]
    else:
        tryRates = [baud]
    for rate in tryRates:
        ser.baudrate = rate
        sendData(ser, "", blocking=False)
        response = sendCmd(ser, "WS", errors=False, blocking=False) # Warm Start
        for line in response:
            if "ELM327" in line:
                idString = line
                recognized = True
                break
 
        if recognized:
            break
 
    if not recognized:
        print("ERROR: ELM327 not found on {}".format(port))
        exit()
    ser.timeout = TIMEOUT
    configureSerial(ser)
    if not baud:
        for rate in [500000, 460800, 230400, 115200, 57600]:
            if trySwitchingBaudRate(ser, rate):
                break
 
    print("{} @ {} bps".format(idString, ser.baudrate))
    print("")
    configureCAN(ser)
    print("Connecting to vehicle...")
 
    sendCmd(ser, "SH7E0") # Set Header to filter for ECU (7E0). Transmission is 7E1
    # TODO: Remove after test
    # response = sendData("220000")
    # print("Reading data...")
    # print("DEBUG: Response to 22 00 00: {}".format(response))
    response = sendData(ser, '1A88') # Read ECU Identification -> Original VIN
    print('Reading VIN...')
    print("VIN: {}".format(response))
    error = True
    response = sendData(ser, "1085") # Start Diagnostic Session -> ECU Flash
    # response = sendData(ser, "1092") # Start Diagnostic Session -> Extended
 
    for line in response:
        if "5085" in line: # Start Diagnostic Session Positive Response
            error = False
 
    if error:
        print("ERROR: could not exit default session")
        exit()
 
    print("Acquiring securityAccess...")
    acquireSecurityAccess(ser, secret)
    print("")
 
    print("Reading ROM...")
    # cmd_str = "230000200000FF" # Read memory by address
    chunk_size = 1024 # Maximum is 4094 according to doc, but errors even with 2048
    address_start = 0
    address_end = 2 ** 19 # 512kb
    ftmp = open(TMPFILE, "w")
    for address in range(address_start, address_end, chunk_size):
        hex_address = int_to_hex(address, 8)
        remaining_bytes = address_end - address
        hex_size = int_to_hex(min(chunk_size, remaining_bytes), 4)
        print(f"Reading {chunk_size} bytes @ 0x{hex_address}")
        cmd_str = f"23{hex_address}{hex_size}" # Read memory by address
        response = sendData(ser, cmd_str)
        ftmp.write(f"Response: {response}"+ "\n")
        #print(f"Response: {response}")
    ftmp.close()
    rom_contents = parse_file(TMPFILE)
    write_hex_str_to_binary(rom_contents,outfile)
 
 
def int_to_hex(number, pad=None):
    hex_string = hex(number)[2:] # Removing 0x
    hex_string = hex_string.zfill(((len(hex_string) + 1) // 2) * 2)
    if pad:
        hex_string = hex_string.zfill(pad)
    return hex_string.upper()
 
 
def sendCmd(ser, string, end=">", errors=True, blocking=True):
    cmd = "AT" + string
    response = sendData(ser, cmd, end, blocking)
    ok = False
    for line in response:
        if "OK" in line:
            ok = True
 
    if not ok and errors:
        print(f"WARNING: ELM327 does not appear to support AT command '{string}' (bad clone?)")
    return response
 
 
def sendData(ser, string, end=">", blocking=True):
    data = string + "\r"
    send(ser, data)
    return receiveResponse(ser, end, blocking)
 
 
def sendLong(ser, string):
    data = string + "\r"
    send(ser, data)
    buffer = ""
    while 1:
        try:
            char = ser.read(1).decode()
        except KeyboardInterrupt:
            raise
        except serial.SerialException:
            print("ERROR: Could not read data from serial port")
            exit()
 
        if len(char) > 0:
            # log(char)
            buffer += char
            if char == ">":
                break
 
    return buffer.splitlines()
 
 
def send(ser, data):
    # log(data + "\n")
    try:
        ser.write(data.encode())
    except KeyboardInterrupt:
        raise
    except serial.SerialException:
        print("ERROR: Could not write data to serial port")
        exit()
 
 
def receiveResponse(ser, end=">", blocking=True):
    buffer = ""
    char = ""
    if blocking:
        charsToRead = 1
    else:
        charsToRead = 20
    while 1:
        try:
            char = ser.read(charsToRead).decode()
        except KeyboardInterrupt:
            raise
        except UnicodeDecodeError:
            pass
        except serial.SerialException:
            print("ERROR: Could not read data from serial port")
            exit()
 
        if len(char) > 0:
            # log(char)
            buffer += char
            if char == end:
                break
        elif not blocking:
            return buffer.splitlines()
 
    response = buffer.splitlines()
    if len(response) < 1 or response[0] in ("NO DATA", "CAN ERROR"):
        print("ERROR: No response from vehicle (is ignition on?)")
        exit()
    return response
 
 
def configureSerial(ser):
    sendCmd(ser, "E0") # Echo off
    sendCmd(ser, "L1") # Linefeeds On
    sendCmd(ser, "R1") # Responses On
    sendCmd(ser, "S0") # Printing of Spaces Off
    sendCmd(ser, "H0") # Headers Off
 
 
def trySwitchingBaudRate(ser, rate):
    ser.timeout = 0.1
    div = round(4000000 / rate)
    try:
        # Set baud rate divisor
        sendCmd(ser, "BRD" + "{:02x}".format(div), end="\r", errors=False)
    except:
        ser.baudrate = BAUD_RATE
        ser.timeout = TIMEOUT
        return False
 
    ser.baudrate = rate
    try:
        response = receiveResponse(ser, end="\r")
    except:
        ser.baudrate = BAUD_RATE
        ser.timeout = TIMEOUT
        return False
 
    recognized = False
    for line in response:
        if "ELM327" in line:
            recognized = True
 
    if not recognized:
        ser.baudrate = BAUD_RATE
        ser.timeout = TIMEOUT
        return False
    response = sendData(ser, "")
    ok = False
    for line in response:
        if "OK" in line:
            ok = True
 
    if not ok:
        ser.baudrate = BAUD_RATE
        ser.timeout = TIMEOUT
        return False
    ser.timeout = TIMEOUT
    return True

def configureCANSpeed(ser):
    #38400, 57600, 115200, 230400, 460800, 500000]
    match ser.baudrate:
        case 57600: sendCmd(ser, "TPF") # Try protocol F (User5 CAN (11* bit ID, 33.3* kbaud) )
        case 57600: sendCmd(ser, "TPC") # Try protocol C (User2 CAN (11* bit ID, 50* kbaud) )
        case 115200: sendCmd(ser, "TPE") # Try protocol 6 (User4 CAN (11* bit ID, 95.2* kbaud) )
        case 230400: sendCmd(ser, "TPB") # Try protocol 6 (User1 CAN (11* bit ID, 125* kbaud) )
        case 460800: sendCmd(ser, "TP8") # Try protocol 6 (ISO 15765-4 CAN (11 bit ID, 250 kbaud) )
        case 500000: sendCmd(ser, "TP6") # Try protocol 6 (ISO15765-4 11-bit CAN protocol at 500kbaud)
        

def configureCAN(ser):
    sendCmd(ser, "CAF1") # CAN Automatic Formatting On
    sendCmd(ser, "AL") # Allow long messages
    sendCmd(ser, "ST96") # Set timeout to 96x4 ms
    sendCmd(ser, "AT0") # Adaptive timing off
    sendCmd(ser, "TA30") # Set Tester Address to 30
    #sendCmd(ser, "TP6") # Try protocol 6 (ISO15765-4 11-bit CAN protocol at 500kbaud)
    configureCANSpeed(ser)

 
 
def acquireSecurityAccess(ser, secret):
    seed = getNewSeed(ser)
    key = key_from_seed(seed, secret)
    accessGranted = tryKey(ser, key)
    if accessGranted:
        print(f"Access granted with secret key ('{stringRep(secret)}')")
        return
    raise RuntimeError(f"Unable to access ROM with secret {secret}")
 
 
def getNewSeed(ser):
    error = True
    response = sendLong(ser, "2701") # Security Access -> Request Seed
    for line in response:
        if "6701" in line: # Security Access Request Seed Positive Response
            error = False
            seed = line[4:]
            break
 
    if error:
        return
    return seed
 
def tryKey(ser, key):
    accessGranted = False
    unusualResponse = True
    response = sendLong(ser, "2702{:06X}".format(key)) # Security Access -> Send Key
    for line in response:
        if "6702" in line:  # Security Access Send Key Positive Response
            accessGranted = True
            unusualResponse = False
            break
        elif "7F2735" in line: # Invalid Key
            unusualResponse = False
 
    if unusualResponse:
        print(f"Unusual response '{response[0]}'")
    return accessGranted
 
def key_from_seed(seed, secret):
    s1 = int(secret[0:2], 16)
    s2 = int(secret[3:5], 16)
    s3 = int(secret[6:8], 16)
    s4 = int(secret[9:11], 16)
    s5 = int(secret[12:14], 16)
    seed_int = (int(seed[0:2], 16) << 16) + (int(seed[2:4], 16) << 8) + int(seed[4:6], 16)
    or_ed_seed = (seed_int & 16711680) >> 16 | seed_int & 65280 | s1 << 24 | (seed_int & 255) << 16
    mucked_value = 12927401
    for i in range(0, 32):
        a_bit = (or_ed_seed >> i & 1 ^ mucked_value & 1) << 23
        v9 = v10 = v8 = a_bit | mucked_value >> 1
        mucked_value = v10 & 15691735 | ((v9 & 1048576) >> 20 ^ (v8 & 8388608) >> 23) << 20 | ((mucked_value >> 1 & 32768) >> 15 ^ (v8 & 8388608) >> 23) << 15 | ((mucked_value >> 1 & 4096) >> 12 ^ (v8 & 8388608) >> 23) << 12 | 32 * ((mucked_value >> 1 & 32) >> 5 ^ (v8 & 8388608) >> 23) | 8 * ((mucked_value >> 1 & 8) >> 3 ^ (v8 & 8388608) >> 23)
 
    for j in range(0, 32):
        a_bit = ((s5 << 24 | s4 << 16 | s2 | s3 << 8) >> j & 1 ^ mucked_value & 1) << 23
        v14 = v13 = v12 = a_bit | mucked_value >> 1
        mucked_value = v14 & 15691735 | ((v13 & 1048576) >> 20 ^ (v12 & 8388608) >> 23) << 20 | ((mucked_value >> 1 & 32768) >> 15 ^ (v12 & 8388608) >> 23) << 15 | ((mucked_value >> 1 & 4096) >> 12 ^ (v12 & 8388608) >> 23) << 12 | 32 * ((mucked_value >> 1 & 32) >> 5 ^ (v12 & 8388608) >> 23) | 8 * ((mucked_value >> 1 & 8) >> 3 ^ (v12 & 8388608) >> 23)
 
    key = (mucked_value & 983040) >> 16 | 16 * (mucked_value & 15) | ((mucked_value & 15728640) >> 20 | (mucked_value & 61440) >> 8) << 8 | (mucked_value & 4080) >> 4 << 16
    return key
 
def stringRep(secret):
    string = ""
    for item in secret.split():
        i = int(item, 16)
        if i >= 32 and i < 127:
            string += chr(i)
        else:
            string += "."
 
    return string
 
def defaultSecret(secret):
    if secret == "NONE":
        if isinstance(Default_KEY, str):
            return Default_KEY
    else:
        return secret


if __name__ == "__main__":
    print("")
    print("*******************************************************")
    print("                Mazda RX-8 ROM Dump")
    print("*******************************************************")
    print("")
    parser = argparse.ArgumentParser(usage="%(prog)s [options] PORT", description="Dump RX-8 PCM, connected via an ELM327 OBDII interface on PORT")
    parser.add_argument("port", metavar="PORT", help="COM port ELM327 adapter is connected to e.g. COM1")
    parser.add_argument("-s", "--secret", metavar="KEY", default="NONE", help="Provide shared secret KEY if known (mapped ROMS)")
    parser.add_argument("-b", "--baud", metavar="RATE", type=int, default=0, help="Manually specify baud RATE instead of autodetect")
    parser.add_argument("-o", "--output", metavar="OUTFILE", default=ROMFILE , help="output file rom.bin as default")
    args = parser.parse_args()
 
    secret = defaultSecret(args.secret)
    dump_rom(args.port, args.baud, secret, args.output)