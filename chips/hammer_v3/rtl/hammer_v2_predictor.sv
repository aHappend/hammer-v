module hammer_v2_predictor #(
    parameter integer PRED_MODE = 1,
    parameter integer BTB_ENTRIES = 16
) (
    input wire clk, rst_n,
    input wire [63:0] pc,
    input wire [31:0] insn,
    output reg [63:0] next_pc,
    input wire update,
    input wire [63:0] update_pc, update_target,
    input wire update_taken, update_conditional
);
    localparam integer LEGAL = (PRED_MODE == 0 || PRED_MODE == 1) &&
        (BTB_ENTRIES == 1 || BTB_ENTRIES == 4 ||
         BTB_ENTRIES == 16 || BTB_ENTRIES == 64);
    initial begin
        if (PRED_MODE != 0 && PRED_MODE != 1)
            $fatal(1, "PARAMETER ERROR: PRED_MODE must be 0 or 1");
        if (BTB_ENTRIES != 1 && BTB_ENTRIES != 4 &&
            BTB_ENTRIES != 16 && BTB_ENTRIES != 64)
            $fatal(1, "PARAMETER ERROR: BTB_ENTRIES must be 1,4,16,64");
    end
    generate if (LEGAL) begin : g_legal
        localparam integer IW = BTB_ENTRIES <= 1 ? 1 : $clog2(BTB_ENTRIES);
        reg [BTB_ENTRIES-1:0] valid, conditional;
        reg [63:0] tags [0:BTB_ENTRIES-1];
        reg [63:0] targets [0:BTB_ENTRIES-1];
        reg [1:0] counters [0:BTB_ENTRIES-1];
        wire [IW-1:0] index = BTB_ENTRIES == 1 ? {IW{1'b0}} : pc[IW+1:2];
        wire [IW-1:0] uindex = BTB_ENTRIES == 1 ? {IW{1'b0}} :
            update_pc[IW+1:2];
        wire hit = valid[index] && tags[index] == pc;
        wire uhit = valid[uindex] && tags[uindex] == update_pc;
        wire [63:0] bimm = {{51{insn[31]}}, insn[31], insn[7],
            insn[30:25], insn[11:8], 1'b0};
        wire [63:0] jimm = {{43{insn[31]}}, insn[31], insn[19:12],
            insn[20], insn[30:21], 1'b0};
        integer n;
        always @* begin
            next_pc = 64'b0;
            if (rst_n) begin
                next_pc = pc + 64'd4;
                if (PRED_MODE == 0) begin
                    if (insn[6:0] == 7'h63 && insn[31]) next_pc = pc + bimm;
                    if (insn[6:0] == 7'h6f) next_pc = pc + jimm;
                end else if (hit && (!conditional[index] || counters[index][1]))
                    next_pc = targets[index];
            end
        end
        always @(posedge clk or negedge rst_n) begin
            if (!rst_n) begin
                valid <= {BTB_ENTRIES{1'b0}};
                conditional <= {BTB_ENTRIES{1'b0}};
                for (n = 0; n < BTB_ENTRIES; n = n + 1) begin
                    tags[n] <= 64'b0;
                    targets[n] <= 64'b0;
                    counters[n] <= 2'b01;
                end
            end else if (update && PRED_MODE == 1) begin
                if (update_conditional) begin
                    if (uhit) begin
                        if (update_taken && counters[uindex] != 2'b11)
                            counters[uindex] <= counters[uindex] + 2'b01;
                        else if (!update_taken && counters[uindex] != 2'b00)
                            counters[uindex] <= counters[uindex] - 2'b01;
                    end else if (update_taken) counters[uindex] <= 2'b10;
                    if (update_taken) begin
                        valid[uindex] <= 1'b1;
                        tags[uindex] <= update_pc;
                        targets[uindex] <= update_target;
                        conditional[uindex] <= 1'b1;
                    end
                end else begin
                    valid[uindex] <= 1'b1;
                    tags[uindex] <= update_pc;
                    targets[uindex] <= update_target;
                    conditional[uindex] <= 1'b0;
                    counters[uindex] <= 2'b01;
                end
            end
        end
    end else begin : g_bad
        assign next_pc = 64'b0;
    end endgenerate
endmodule
