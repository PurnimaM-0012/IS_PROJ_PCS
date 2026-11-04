"""
kernel_bitmap_dump.py  --  Volatility3 extension (load with `vol -p vol_plugins`)
---------------------------------------------------------------------------------
Adds support for Windows *kernel bitmap* crash dumps (DumpType 0x6), which is
what Task Manager's "Create live kernel memory dump file" produces.

Stock Volatility3 (2.28) only accepts DumpType 0x1 (full) and 0x5 (full
bitmap). A kernel bitmap dump uses the same on-disk layout as 0x5 -- a
_SUMMARY_DUMP header ("SDMP" instead of "FDMP") followed by a page bitmap and
the present pages -- it just contains fewer pages (kernel memory only, no
user-mode pages). So we reuse the 0x5 segment loader for 0x6.
"""

import logging
from typing import Optional

from volatility3.framework import constants, interfaces
from volatility3.framework.layers.crash import (WindowsCrashDump64Layer,
                                                WindowsCrashDumpFormatException)

vollog = logging.getLogger(__name__)

DUMP_TYPE_BITMAP_FULL = 0x5
DUMP_TYPE_BITMAP_KERNEL = 0x6


class WindowsKernelBitmapDump64Layer(WindowsCrashDump64Layer):
    """64-bit Windows crash dump layer that also accepts kernel bitmap dumps."""

    supported_dumptypes = [0x1, DUMP_TYPE_BITMAP_FULL, DUMP_TYPE_BITMAP_KERNEL]

    def _load_segments(self) -> None:
        if self.dump_type != DUMP_TYPE_BITMAP_KERNEL:
            return super()._load_segments()
        self.dump_type = DUMP_TYPE_BITMAP_FULL  # identical bitmap layout
        try:
            super()._load_segments()
        finally:
            self.dump_type = DUMP_TYPE_BITMAP_KERNEL


class WindowsKernelBitmapDumpStacker(interfaces.automagic.StackerLayerInterface):
    stack_order = 10  # run just before the stock crash-dump stacker (11)

    @classmethod
    def stack(cls, context: interfaces.context.ContextInterface, layer_name: str,
              progress_callback: constants.ProgressCallback = None
              ) -> Optional[interfaces.layers.DataLayerInterface]:
        layer = WindowsKernelBitmapDump64Layer
        try:
            layer.check_header(context.layers[layer_name])
            new_name = context.layers.free_layer_name(layer.__name__)
            context.config[interfaces.configuration.path_join(new_name, "base_layer")] = layer_name
            return layer(context, new_name, new_name)
        except WindowsCrashDumpFormatException as excp:
            vollog.log(constants.LOGLEVEL_VVVV, f"Not a kernel bitmap dump: {excp}")
        return None
