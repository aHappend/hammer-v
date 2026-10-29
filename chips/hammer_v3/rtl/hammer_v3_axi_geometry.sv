module hammer_v3_axi_geometry #(
    parameter integer DMEM_WORDS = 8192
) (
    input wire [63:0] addr,
    input wire [7:0] len,
    input wire [2:0] size,
    input wire [1:0] burst,
    input wire lock,
    output wire geometry_error, address_error
);
    localparam [64:0] DMEM_END = 65'h10000000 + DMEM_WORDS * 65'd8;
    wire [64:0] beat_bytes = 65'd1 << size;
    wire [64:0] span = burst == 1 ?
        (({57'b0,len} + 65'd1) << size) : beat_bytes;
    wire [64:0] last_byte = {1'b0,addr} + span - 65'd1;
    wire legacy_region = addr >= 64'h10000000 &&
        {1'b0,addr} < DMEM_END && last_byte < DMEM_END;
    wire external_region = addr >= 64'h80000000 && addr < 64'h100000000 &&
        last_byte < 65'h100000000;
    initial begin
        if (DMEM_WORDS < 1 || DMEM_WORDS > 8192)
            $fatal(1, "PARAMETER ERROR: accelerator DMEM_WORDS must be 1..8192");
    end
    assign geometry_error = len > 15 || size > 3 || burst > 1 || lock ||
        |({1'b0,addr} & (beat_bytes - 65'd1)) || last_byte[64] ||
        last_byte[63:12] != addr[63:12];
    assign address_error = !(legacy_region || external_region) || last_byte[64];
endmodule
