#!/usr/bin/env python3
"""Compare independent UART MMIO, interrupt and pin timing with a real leaf.

The bounded Icarus fixture observes every released edge. Its expectations are
computed before compilation; no UART observations feed the Python platform.
"""

import argparse
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from system_oracle import Clock, Phase, canonical_json, digest
from system_platform import Platform


BENCH = r"""
module tb;
  reg clk=0, rst_n=0, uart_rx=1, req_valid=0, req_write=0, rsp_ready=1;
  reg [63:0] req_addr=0, req_wdata=0;
  reg [1:0] req_size=0;
  reg [7:0] req_wstrb=0;
  wire uart_tx, irq, req_ready, rsp_valid, rsp_error;
  wire [63:0] rsp_rdata;
  hammer_v3_uart dut(.*);
  integer fd, n, edge_id, rx, valid, wr, offset, data;
  integer want_tx, want_irq, reply, want_error, cycles=0, accesses=0;
  reg [63:0] want_data;
  reg [1023:0] vectors;
  initial begin
    if (!$value$plusargs("vectors=%s", vectors)) $fatal(1,"missing vectors");
    fd=$fopen(vectors,"r");
    if (!fd) $fatal(1,"cannot read vectors");
    repeat(4) begin #5 clk=1; #5 clk=0; end
    rst_n=1;
    while (!$feof(fd)) begin
      n=$fscanf(fd,"%d %d %d %d %d %d %d %d %d %h %d\n",
                edge_id,rx,valid,wr,offset,data,want_tx,want_irq,reply,want_data,want_error);
      if (n != 11) $fatal(1,"malformed vector");
      req_valid=valid; req_write=wr; req_addr=64'h10010000+offset;
      req_wdata=64'(data) << (8*offset); req_wstrb=8'b1 << offset; uart_rx=rx;
      #4;
      if (valid && req_ready !== 1'b1) $fatal(1,"UART_READY edge=%0d",edge_id);
      #1 clk=1; #1;
      if (uart_tx !== 1'(want_tx) || irq !== 1'(want_irq))
        $fatal(1,"UART_PIN edge=%0d tx=%0b/%0b irq=%0b/%0b",
               edge_id,uart_tx,1'(want_tx),irq,1'(want_irq));
      if (reply && (rsp_valid !== 1'b1 || rsp_error !== 1'(want_error) ||
                    rsp_rdata !== want_data))
        $fatal(1,"UART_RESPONSE edge=%0d data=%h/%h error=%0b/%0b",
               edge_id,rsp_rdata,want_data,rsp_error,1'(want_error));
      cycles=cycles+1; if (valid) accesses=accesses+1;
      #4 clk=0;
    end
    $display("COMPARED_UART_PLATFORM edges=%0d accesses=%0d",cycles,accesses);
    $finish;
  end
endmodule
"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    relative = Path(args.out)
    if relative.is_absolute() or ".." in relative.parts or relative.parts[:1] != ("build",):
        parser.error("--out must be a fresh project-relative build directory")
    out = ROOT / relative
    out.mkdir(parents=True, exist_ok=False)
    clock = Clock()
    platform = Platform(clock, lambda *_: None)
    requests = {
        8: (3, True, 3), 16: (2, True, 1), 24: (1, True, 3),
        32: (2, False, 0), 40: (0, True, 0xA5), 48: (5, False, 0),
        56: (2, False, 0), 64: (0, True, 0x5A), 400: (2, False, 0),
        416: (1, True, 0), 424: (2, True, 0x41), 432: (1, True, 1),
        1200: (2, False, 0), 1216: (5, False, 0),
        1232: (0, False, 0), 1248: (2, False, 0), 1264: (5, False, 0),
        1280: (2, True, 3), 1296: (2, False, 0),
    }
    replies = {}
    for edge, (offset, store, value) in requests.items():
        def sample(e=edge, o=offset, s=store, v=value):
            platform._uart(e, 0x10010000 + o, 1, s, v,
                           lambda reply: replies.__setitem__(e, reply))
        clock.schedule(edge, Phase.SAMPLE, sample)
    previous = 1
    rx_levels = {}
    for bit, level in enumerate((0, 1, 0, 1, 0, 0, 1, 0, 1, 1)):
        edge = 500 + bit * 16
        if level != previous:
            platform.receiver.transition(edge, level)
            rx_levels[edge] = level
            previous = level
    rows = []
    rx = 1
    for edge in range(1500):
        rx = rx_levels.get(edge, rx)
        clock.run(edge)
        offset, store, value = requests.get(edge, (0, False, 0))
        reply = replies.get(edge)
        rows.append(
            f"{edge} {rx} {int(edge in requests)} {int(store)} {offset} {value} "
            f"{platform.transmitter.line} {int(not platform.iir() & 1)} "
            f"{int(reply is not None)} "
            f"{(reply.data << (8 * offset)) if reply else 0:x} "
            f"{int(reply.error) if reply else 0}\n"
        )
    (out / "vectors.txt").write_text("".join(rows), encoding="ascii")
    (out / "bridge.sv").write_text(BENCH, encoding="ascii")
    commands = [
        ["iverilog", "-g2012", "-Wall", "-s", "tb", "-o",
         (relative / "sim").as_posix(), "rtl/hammer_v3_uart.sv",
         (relative / "bridge.sv").as_posix()],
        ["vvp", (relative / "sim").as_posix(),
         "+vectors=" + (relative / "vectors.txt").as_posix()],
    ]
    records = []
    for index, argv in enumerate(commands):
        record = {"argv": argv, "cwd": ".", "exit_code": None}
        records.append(record)
        with (out / f"{index}.stdout.log").open("wb") as so, (
            out / f"{index}.stderr.log"
        ).open("wb") as se:
            result = subprocess.run(argv, cwd=ROOT, stdout=so, stderr=se, check=False)
        record["exit_code"] = result.returncode
        (out / "commands.json").write_bytes(canonical_json(records))
        if result.returncode:
            raise AssertionError(f"UART platform stage {index} failed; {relative}/{index}.stdout.log")
    (out / "summary.json").write_bytes(canonical_json({
        "scope": "bounded UART platform model comparison, not Linux acceptance",
        "compared_edges": len(rows), "compared_mmio": len(requests),
        "vectors_sha256": digest(out / "vectors.txt"),
    }))
    print(f"COMPARED_UART_PLATFORM edges={len(rows)} mmio={len(requests)}")


if __name__ == "__main__":
    main()
