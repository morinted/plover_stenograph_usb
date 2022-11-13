from itertools import compress
from struct import Struct, calcsize, pack, unpack
from time import sleep

import sys
from typing import Optional

from more_itertools import grouper
from plover.machine.base import ThreadedStenotypeBase
from plover import log

'''
Packet format:
--------------
Name:     Size:       Value Range:
----------------------------------
Sync          2 bytes "SG"
Sequence #    4 bytes 0 - 0xFFFFFFFF (will wrap from 0xFFFFFFFF to 0x00000000)
Packet ID     2 bytes As Defined (used as packet type)
Data Length   4 bytes 0 - size (limited in most writers to 65536 bytes)
Parameter 1   4 bytes As Defined
Parameter 2   4 bytes As Defined
Parameter 3   4 bytes As Defined
Parameter 4   4 bytes As Defined
Parameter 5   4 bytes As Defined

Command 0x13 Read Bytes
-----------------------

Request (from PC)
Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Read Bytes   0x0013       00000000          File Offset   Byte Count  00000000    00000000    00000000

-Parameter 1 contains the file offset from which the Mira should start returning bytes (or stroke number * 8 since there are 8 bytes returned per stroke (see details of Response))
-Parameter 2 contains the maximum number of bytes the Host wants the Mira to send in response to this request
-The Mira will respond to this packet with a successful Read Bytes packet or an Error packet.

Response (from Mira)
Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Read Bytes    0x0013      Number of Bytes   File Offset   00000000    00000000    00000000    00000000

-Parameter 1 contains the file offset from which the Mira is returning bytes
-For real-time the data is four bytes of steno and 4 bytes of timestamp - 8 bytes per stroke - repeating for the number of strokes returned.
The format of the eight bytes will be:
-Byte 0: 11^#STKP
-Byte 1: 11WHRAO*
-Byte 2: 11EUFRPB
-Byte 3: 11LGTSDZ
-Bytes 4-7: 'timestamp'
-The steno is in the (very) old SmartWriter format where the top two bits of each of the four bytes are set to 1 and the bottom 6 bits as set according to the keys pressed.
-If the Data Length is zero that indicates there are no more bytes available (real-time).
-If the file has been closed (on the writer) an Error packet (error: FileClosed) will be sent in response to Read Bytes.

Description   Packet ID   Data Length       Param 1       Param 2     Param 3     Param 4     Param 5
------------------------------------------------------------------------------------------------------
Open File     0x0012      Number of Bytes   Disk ID

- Parameter 1 is the disk ID that the file you wish to open is on (disk A for all intents and purposes)
- Data is the filename, probably 'REALTIME.000'
'''

# ^ is the "stenomark"
STENO_KEY_CHART = (
    ('^', '#', 'S-', 'T-', 'K-', 'P-'),
    ('W-', 'H-', 'R-', 'A-', 'O-', '*'),
    ('-E', '-U', '-F', '-R', '-P', '-B'),
    ('-L', '-G', '-T', '-S', '-D', '-Z'),
)

VENDOR_ID = 0x112b
MAX_READ = 0x200  # Arbitrary read limit


class StenoPacket:
    """
    Stenograph StenoPacket helper

    Can be used to create packets to send to the writer, as well as
    decode a packet from the writer.
    """
    _SYNC = b'SG'

    """
    Packet header format:
    'SG'     sequence number  packet ID  data length p1,p2,p3,p4,p5
    2 chars  4 bytes          2 bytes    4 bytes     4 bytes each
    """
    _STRUCT_FORMAT = '<2sIH6I'
    HEADER_SIZE = calcsize(_STRUCT_FORMAT)
    _STRUCT = Struct(_STRUCT_FORMAT)

    ID_ERROR = 0x6
    ID_OPEN = 0x11
    ID_READ = 0x13


    sequence_number = 0

    def __init__(self, sequence_number=None, packet_id=0, data_length=None,
                 p1=0, p2=0, p3=0, p4=0, p5=0, data=b''):
        """Create a USB Packet

        sequence_number -- ideally unique, if not passed one will be assigned sequentially.

        packet_id -- type of packet.

        data_length -- length of the additional data, calculated if not provided.

        p1, p2, p3, p4, p5 -- 4 byte parameters that have different roles based on packet_id

        data -- data to be appended to the end of the packet, used for steno strokes from the writer.
        """
        if sequence_number is None:
            sequence_number = StenoPacket.sequence_number
            StenoPacket._increment_sequence_number()
        if data is not None:
            # Data is padded to 8 bytes
            remainder = len(data) % 8
            if remainder:
                data += b'\x00' * (8 - remainder)
        if data_length is None:
            data_length = len(data)
        self.sequence_number = sequence_number
        self.packet_id = packet_id
        self.data_length = data_length
        self.p1 = p1
        self.p2 = p2
        self.p3 = p3
        self.p4 = p4
        self.p5 = p5
        self.data = data

    def __str__(self):
        return (
            'StenoPacket(sequence_number=%s, '
            'packet_id=%s, data_length=%s, '
            'p1=%s, p2=%s, p3=%s, p4=%s, p5=%s, data=%s)'
            % (hex(self.sequence_number), hex(self.packet_id),
               self.data_length, hex(self.p1), hex(self.p2),
               hex(self.p3), hex(self.p4), hex(self.p5),
               self.data[:self.data_length])
        )

    def pack(self):
        """Convert this USB Packet into something that can be sent to the writer."""
        return self._STRUCT.pack(
            self._SYNC, self.sequence_number, self.packet_id, self.data_length,
            self.p1, self.p2, self.p3, self.p4, self.p5
        ) + (
            pack('%ss' % len(self.data), self.data)
        )

    @staticmethod
    def _increment_sequence_number():
        StenoPacket.sequence_number = (StenoPacket.sequence_number + 1) % 0xFFFFFFFF

    @staticmethod
    def unpack(usb_packet):
        """Create a USBPacket from raw data"""
        packet = StenoPacket(
            # Drop sync when unpacking.
            *StenoPacket._STRUCT.unpack(usb_packet[:StenoPacket.HEADER_SIZE])[1:]
        )
        if packet.data_length:
            packet.data, = unpack(
                '%ss' % packet.data_length,
                usb_packet[StenoPacket.HEADER_SIZE:StenoPacket.HEADER_SIZE + packet.data_length]
            )
        return packet

    @staticmethod
    def make_open_request(file_name=b'REALTIME.000', disk_id=b'A'):
        """Request to open a file on the writer, defaults to the realtime file."""
        return StenoPacket(
            packet_id=StenoPacket.ID_OPEN,
            p1=ord(disk_id) if disk_id else 0, # Omitting p1 may use the default drive.
            data=file_name,
        )

    @staticmethod
    def make_read_request(file_offset=1, byte_count=MAX_READ):
        """Request to read from the writer, defaults to settings required when reading from realtime file."""
        return StenoPacket(
            packet_id=StenoPacket.ID_READ,
            p1=file_offset,
            p2=byte_count,
        )

    def strokes(self):
        """Get list of strokes represented in this packet's data"""

        # Expecting 8-byte chords (4 bytes of steno, 4 of timestamp.)
        assert self.data_length % 8 == 0
        # Steno should only be present on ACTION_READ packets
        assert self.packet_id == self.ID_READ

        strokes = []
        for stroke_data in grouper(self.data, 8, fillvalue=0):
            stroke = []
            # Get 4 bytes of steno, ignore timestamp.
            for steno_byte, key_chart_row in zip(stroke_data, STENO_KEY_CHART):
                assert steno_byte >= 0b11000000
                # Only interested in right 6 values
                key_mask = [int(i) for i in bin(steno_byte)[-6:]]
                stroke.extend(compress(key_chart_row, key_mask))
            if stroke:
                strokes.append(stroke)
        return strokes


class AbstractStenographMachine:
    """Simple interface to connect with and send data to a Stenograph machine"""

    def connect(self) -> bool:
        """Connect to machine, returns connection status"""
        raise NotImplementedError('connect() is not implemented')

    def disconnect(self):
        """Disconnect from the machine"""
        raise NotImplementedError('disconnect() is not implemented')

    def send_receive(self, request: StenoPacket) -> Optional[StenoPacket]:
        """Send a StenoPacket to the machine and return the response or None"""
        raise NotImplementedError('send_receive() is not implemented')


if sys.platform.startswith('win32'):

    # For Windows we directly call Windows API functions.

    from ctypes import windll, wintypes
    import ctypes
    import uuid

    GUID = wintypes.BYTE * 16
    HDEVINFO = wintypes.HANDLE

    # Stubs.
    LPOVERLAPPED = wintypes.LPVOID
    LPSECURITY_ATTRIBUTES = wintypes.LPVOID
    PSP_DEVINFO_DATA = wintypes.LPVOID

    # Class GUID for Stenograph USB Writer.
    USB_WRITER_GUID = GUID(*uuid.UUID('{c5682e20-8059-604a-b761-77c4de9d5dbf}').bytes)

    class SP_DEVICE_INTERFACE_DATA(ctypes.Structure):
        _fields_ = [
            ('cbSize', wintypes.DWORD),
            ('InterfaceClassGuid', GUID),
            ('Flags', wintypes.DWORD),
            ('Reserved', wintypes.PULONG),
        ]
    PSP_DEVICE_INTERFACE_DATA = ctypes.POINTER(SP_DEVICE_INTERFACE_DATA)

    class SP_DEVICE_INTERFACE_DETAIL_DATA_A(ctypes.Structure):
        _fields_ = [
            ('cbSize', wintypes.DWORD),
            ('_DevicePath', wintypes.CHAR * 1),
        ]
        @property
        def DevicePath(self):
            return ctypes.string_at(ctypes.byref(self, ctypes.sizeof(wintypes.DWORD)))
    PSP_DEVICE_INTERFACE_DETAIL_DATA_A = ctypes.POINTER(SP_DEVICE_INTERFACE_DETAIL_DATA_A)

    SetupDiGetClassDevs = windll.setupapi.SetupDiGetClassDevsA
    SetupDiGetClassDevs.argtypes = [
        ctypes.POINTER(GUID), # ClassGuid
        wintypes.LPCWSTR,     # Enumerator
        wintypes.HWND,        # hwndParent
        wintypes.DWORD,       # Flags
    ]
    SetupDiGetClassDevs.restype = HDEVINFO

    SetupDiDestroyDeviceInfoList = windll.setupapi.SetupDiDestroyDeviceInfoList
    SetupDiDestroyDeviceInfoList.argtypes = [
        HDEVINFO, # DeviceInfoSet
    ]
    SetupDiDestroyDeviceInfoList.restype = wintypes.BOOL

    SetupDiEnumDeviceInterfaces = windll.setupapi.SetupDiEnumDeviceInterfaces
    SetupDiEnumDeviceInterfaces.argtypes = [
        HDEVINFO,                  # DeviceInfoSet
        PSP_DEVINFO_DATA,          # DeviceInfoData
        ctypes.POINTER(GUID),      # InterfaceClassGuid
        wintypes.DWORD,            # MemberIndex
        PSP_DEVICE_INTERFACE_DATA, # DeviceInterfaceData
    ]
    SetupDiEnumDeviceInterfaces.restype = wintypes.BOOL

    SetupDiGetDeviceInterfaceDetail = windll.setupapi.SetupDiGetDeviceInterfaceDetailA
    SetupDiGetDeviceInterfaceDetail.argtypes = [
        HDEVINFO,                           # DeviceInfoSet
        PSP_DEVICE_INTERFACE_DATA,          # DeviceInterfaceData
        PSP_DEVICE_INTERFACE_DETAIL_DATA_A, # DeviceInterfaceDetailData
        wintypes.DWORD,                     # DeviceInterfaceDetailDataSize
        wintypes.PDWORD,                    # RequiredSize
        PSP_DEVINFO_DATA,                   # DeviceInfoData
    ]
    SetupDiGetDeviceInterfaceDetail.restype = wintypes.BOOL

    CreateFile = windll.kernel32.CreateFileA
    CreateFile.argtypes = [
        wintypes.LPCSTR,       # lpFileName
        wintypes.DWORD,        # dwDesiredAccess
        wintypes.DWORD,        # dwShareMode
        LPSECURITY_ATTRIBUTES, # lpSecurityAttributes
        wintypes.DWORD,        # dwCreationDisposition
        wintypes.DWORD,        # dwFlagsAndAttributes
        wintypes.HANDLE,       # hTemplateFile
    ]
    CreateFile.restype = wintypes.HANDLE

    ReadFile = windll.kernel32.ReadFile
    ReadFile.argtypes = [
        wintypes.HANDLE,  # hFile
        wintypes.LPVOID,  # lpBuffer
        wintypes.DWORD,   # nNumberOfBytesToRead
        wintypes.LPDWORD, # lpNumberOfBytesRead
        LPOVERLAPPED,     # lpOverlapped
    ]
    ReadFile.restype = wintypes.BOOL

    WriteFile = windll.kernel32.WriteFile
    WriteFile.argtypes = [
        wintypes.HANDLE,  # hFile
        wintypes.LPCVOID, # lpBuffer
        wintypes.DWORD,   # nNumberOfBytesToWrite
        wintypes.LPDWORD, # lpNumberOfBytesWritten
        LPOVERLAPPED,     # lpOverlapped
    ]
    WriteFile.restype = wintypes.BOOL

    CloseHandle = windll.kernel32.CloseHandle
    CloseHandle.argtypes = [
        wintypes.HANDLE, # hObject
    ]
    CloseHandle.restype = wintypes.BOOL

    # Defines.

    CREATE_ALWAYS = 2
    CREATE_NEW    = 1

    DIGCF_DEVICEINTERFACE = 0x00000010
    DIGCF_PRESENT         = 0x00000002

    ERROR_INSUFFICIENT_BUFFER = 0x0000007A
    ERROR_NO_MORE_ITEMS       = 0x00000103

    FILE_ATTRIBUTE_NORMAL = 0x80

    FILE_SHARE_READ  = 0x00000001
    FILE_SHARE_WRITE = 0x00000002

    GENERIC_READ  = 0x80000000
    GENERIC_WRITE = 0x40000000

    INVALID_HANDLE_VALUE = -1

    class StenographMachine:

        def __init__(self):
            self._usb_device = INVALID_HANDLE_VALUE
            self._read_buffer = ctypes.create_string_buffer(MAX_READ + StenoPacket.HEADER_SIZE)

        @staticmethod
        def _open_device_instance(device_info, guid):
            dev_interface_data = SP_DEVICE_INTERFACE_DATA()
            dev_interface_data.cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DATA)

            if not SetupDiEnumDeviceInterfaces(
                device_info, None, ctypes.byref(guid),
                0, ctypes.byref(dev_interface_data)
            ):
                if ctypes.GetLastError() != ERROR_NO_MORE_ITEMS:
                    log.error('SetupDiEnumDeviceInterfaces: %s', ctypes.WinError())
                return INVALID_HANDLE_VALUE

            request_length = wintypes.DWORD(0)
            status = SetupDiGetDeviceInterfaceDetail(
                device_info,
                ctypes.byref(dev_interface_data),
                # Call with (None, 0) to see how big a buffer is needed.
                None, 0,
                ctypes.pointer(request_length),
                None,
            )
            if status or ctypes.GetLastError() != ERROR_INSUFFICIENT_BUFFER:
                log.debug('last error not insufficient buffer: %s', ctypes.WinError())
                return INVALID_HANDLE_VALUE

            dev_detail_data_buffer = ctypes.create_string_buffer(request_length.value)
            dev_detail_data_ptr = ctypes.cast(dev_detail_data_buffer, PSP_DEVICE_INTERFACE_DETAIL_DATA_A)
            dev_detail_data_ptr[0].cbSize = ctypes.sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_A)

            # Now put the actual detail data into the buffer
            if not SetupDiGetDeviceInterfaceDetail(
                device_info,
                ctypes.byref(dev_interface_data),
                dev_detail_data_ptr,
                ctypes.sizeof(dev_detail_data_buffer),
                None,
                None,
            ):
                log.error('SetupDiGetDeviceInterfaceDetail: %s', ctypes.WinError())
                return INVALID_HANDLE_VALUE

            device_path = dev_detail_data_ptr[0].DevicePath

            log.debug('okay, creating file, device path: %s', device_path)

            handle = CreateFile(device_path,
                                GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE,
                                None,
                                CREATE_ALWAYS | CREATE_NEW,
                                FILE_ATTRIBUTE_NORMAL,
                                None)
            if handle == INVALID_HANDLE_VALUE:
                log.error('CreateFile: %s', ctypes.WinError())
            return handle

        @staticmethod
        def _open_device_by_class_interface_and_instance(class_guid):
            device_info = SetupDiGetClassDevs(ctypes.byref(class_guid), None, None,
                                              DIGCF_DEVICEINTERFACE | DIGCF_PRESENT)
            if device_info == INVALID_HANDLE_VALUE:
                log.error('SetupDiGetClassDevs: %s', ctypes.WinError())
                return INVALID_HANDLE_VALUE
            usb_device = StenographMachine._open_device_instance(device_info, class_guid)
            if not SetupDiDestroyDeviceInfoList(device_info):
                log.error('SetupDiDestroyDeviceInfoList: %s', ctypes.WinError())
            return usb_device

        def _usb_write_packet(self, request):
            bytes_written = wintypes.DWORD(0)
            request_packet = request.pack()
            if not WriteFile(self._usb_device,
                             request_packet,
                             StenoPacket.HEADER_SIZE + request.data_length,
                             ctypes.byref(bytes_written),
                             None):
                log.error('WriteFile: %s', ctypes.WinError())
                return 0
            return bytes_written.value

        def _usb_read_packet(self):
            bytes_read = wintypes.DWORD(0)
            if not ReadFile(self._usb_device,
                            self._read_buffer,
                            MAX_READ + StenoPacket.HEADER_SIZE,
                            ctypes.byref(bytes_read),
                            None):
                log.error('ReadFile: %s', ctypes.WinError())
                return None
            # Return None if not enough data was read.
            if bytes_read.value < StenoPacket.HEADER_SIZE:
                log.error('ReadFile: short read, %u < %u',
                          bytes_read.value, StenoPacket.HEADER_SIZE)
                return None
            writer_packet = StenoPacket.unpack(self._read_buffer)
            return writer_packet

        def disconnect(self):
            if not CloseHandle(self._usb_device):
                log.error('CloseHandle: %s', ctypes.WinError())
            self._usb_device = INVALID_HANDLE_VALUE

        def connect(self):
            # If already connected, disconnect first.
            if self._usb_device != INVALID_HANDLE_VALUE:
                self.disconnect()
            self._usb_device = self._open_device_by_class_interface_and_instance(USB_WRITER_GUID)
            return self._usb_device != INVALID_HANDLE_VALUE

        def send_receive(self, request):
            assert self._usb_device != INVALID_HANDLE_VALUE, 'device not open'
            written = self._usb_write_packet(request)
            if written < StenoPacket.HEADER_SIZE:
                # We were not able to write the request.
                return None
            writer_packet = self._usb_read_packet()
            return writer_packet

else:

    from usb import core, util

    from pyusb_libusb1_backend import get_pyusb_backend

    class StenographMachine(AbstractStenographMachine):

        def __init__(self):
            super().__init__()
            self._usb_device = None
            self._endpoint_in = None
            self._endpoint_out = None
            self._connected = False

        def connect(self):
            """Attempt to and return connection"""
            # Disconnect device if it's already connected.
            if self._connected:
                self.disconnect()

            backend = get_pyusb_backend()

            # Find the device by the vendor ID.
            usb_device = core.find(backend=backend, idVendor=VENDOR_ID)
            if not usb_device:  # Device not found
                return self._connected

            # Copy the default configuration.
            usb_device.set_configuration()
            config = usb_device.get_active_configuration()
            interface = config[(0, 0)]

            # Get the write endpoint.
            endpoint_out = util.find_descriptor(
                interface,
                custom_match=lambda e:
                    util.endpoint_direction(e.bEndpointAddress) ==
                    util.ENDPOINT_OUT
            )
            assert endpoint_out is not None, 'cannot find write endpoint'

            # Get the read endpoint.
            endpoint_in = util.find_descriptor(
                interface,
                custom_match=lambda e:
                    util.endpoint_direction(e.bEndpointAddress) ==
                    util.ENDPOINT_IN
            )
            assert endpoint_in is not None, 'cannot find read endpoint'

            self._usb_device = usb_device
            self._endpoint_in = endpoint_in
            self._endpoint_out = endpoint_out
            self._connected = True
            return self._connected

        def disconnect(self):
            self._connected = False
            util.dispose_resources(self._usb_device)
            self._usb_device = None
            self._endpoint_in = None
            self._endpoint_out = None

        def send_receive(self, request):
            assert self._connected, 'cannot read from machine if not connected'
            try:
                self._endpoint_out.write(request.pack())
                response = self._endpoint_in.read(
                    MAX_READ + StenoPacket.HEADER_SIZE, 3000)
            except core.USBError:
                return None
            else:
                if response and len(response) >= StenoPacket.HEADER_SIZE:
                    writer_packet = StenoPacket.unpack(response)
                    # Ignore data if sequence numbers don't match.
                    if writer_packet.sequence_number == request.sequence_number:
                        return writer_packet
                return None


class ProtocolViolationException(Exception):
    """The writer did something unexpected"""


class UnableToPerformRequestException(Exception):
    """The writer cannot perform the action requested"""


class FileNotAvailableException(Exception):
    """The writer cannot read from the current file"""


class NoRealtimeFileException(Exception):
    """The realtime file doesn't exist, likely because the user hasn't started writing"""


class FinishedReadingClosedFileException(Exception):
    """The closed file being read is complete and cannot be read further"""


class Stenograph(ThreadedStenotypeBase):

    KEYS_LAYOUT = '''
        #  #  #  #  #  #  #  #  #  #
        S- T- P- H- * -F -P -L -T -D
        S- K- W- R- * -R -B -G -S -Z
              A- O-   -E -U
        ^
    '''
    KEYMAP_MACHINE_TYPE = 'Stentura'

    def __init__(self, params):
        super().__init__()
        self._machine = StenographMachine()

    def _on_stroke(self, keys):
        steno_keys = self.keymap.keys_to_actions(keys)
        if steno_keys:
            self._notify(steno_keys)

    def start_capture(self):
        self.finished.clear()
        self._initializing()
        # Begin listening for output from the stenotype machine.
        if not self._connect_machine():
            log.warning('Stenograph machine is not connected')
            self._error()
        else:
            self._ready()
            self.start()

    def _connect_machine(self):
        try:
            return self._machine.connect()
        except Exception:
            log.warning('Error connecting', exc_info=True)
            self._error()
        return False

    def _reconnect(self):
        self._initializing()
        connected = False
        while not self.finished.isSet() and not connected:
            sleep(0.25)
            connected = self._connect_machine()
        return connected

    def _send_receive(self, request):
        """Send a StenoPacket and return the response or raise exceptions."""
        log.debug('Requesting from Stenograph: %s', request)
        response = self._machine.send_receive(request)
        log.debug('Response from Stenograph: %s', response)
        if response is None:
            # No response implies device connection issue.
            raise IOError()
        if response.packet_id == StenoPacket.ID_ERROR:
            # Writer may reply with an error packet.
            error_number = response.p1
            if error_number == 3:
                raise UnableToPerformRequestException()
            if error_number == 7:
                raise FileNotAvailableException()
            if error_number == 8:
                raise NoRealtimeFileException()
            if error_number == 9:
                raise FinishedReadingClosedFileException()
            raise RuntimeError('unknown response error: %u' % error_number)
        # Writer has returned a packet.
        if (response.packet_id != request.packet_id
            or response.sequence_number != request.sequence_number):
            raise ProtocolViolationException()
        return response

    def run(self):

        class ReadState:

            def __init__(self):
                self.realtime = False  # Not realtime until we get a 0-length response
                self.realtime_file_open = False  # We are reading from a file
                self.offset = 0  # File offset to read from

            def reset(self):
                self.__init__()

        state = ReadState()

        while not self.finished.isSet():
            try:
                if not state.realtime_file_open:
                    # Open realtime file
                    self._send_receive(StenoPacket.make_open_request())
                    state.realtime_file_open = True
                response = self._send_receive(
                    StenoPacket.make_read_request(file_offset=state.offset)
                )
            except IOError as e:
                log.warning('Stenograph machine disconnected, reconnecting…')
                log.debug('Stenograph exception: %s', e)
                # User could start a new file while disconnected.
                state.reset()
                if self._reconnect():
                    log.warning('Stenograph reconnected.')
                    self._ready()
            except NoRealtimeFileException:
                log.debug('NoRealtimeFileException')
                # User hasn't started writing, just keep opening the realtime file
                state.reset()
            except FinishedReadingClosedFileException:
                log.debug('FinishedReadingClosedFileException')
                # File closed! Open the realtime file.
                state.reset()
            else:
                log.debug('response length: %u', response.data_length)
                if response.data_length:
                    state.offset += response.data_length
                elif not state.realtime:
                    log.debug('state realtime')
                    state.realtime = True
                if response.data_length and state.realtime:
                    for stroke in response.strokes():
                        self._on_stroke(stroke)
                sleep(0.10)

        self._machine.disconnect()

    def stop_capture(self):
        """Stop listening for output from the stenotype machine."""
        super().stop_capture()
        self._machine = None
        self._stopped()
