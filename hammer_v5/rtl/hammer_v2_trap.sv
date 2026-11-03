module hammer_v2_trap (
    input wire rst_n,
    input wire [1:0] priv,
    input wire [63:0] mstatus, mie, mip, medeleg, mideleg, mtvec, stvec,
    input wire sync_valid,
    input wire [63:0] sync_pc, sync_cause, sync_tval,
    input wire boundary_valid,
    input wire [63:0] boundary_pc,
    output reg enter, interrupt,
    output reg [1:0] target_priv,
    output reg [63:0] epc, cause, tval, vector,
    output wire wake
);
    wire [63:0] locally_pending = mie & mip & 64'haaa;
    reg found, delegated, eligible;
    reg [3:0] selected;
    reg [3:0] candidate;
    reg [63:0] selected_vector;
    integer n;
    assign wake = rst_n && |locally_pending;
    always @* begin
        enter = 1'b0;
        interrupt = 1'b0;
        target_priv = 2'b0;
        epc = 64'b0;
        cause = 64'b0;
        tval = 64'b0;
        vector = 64'b0;
        found = 1'b0;
        delegated = 1'b0;
        eligible = 1'b0;
        selected = 4'b0;
        candidate = 4'b0;
        selected_vector = 64'b0;
        for (n = 0; n < 6; n = n + 1) begin
            case (n)
                0: candidate = 4'd11;
                1: candidate = 4'd3;
                2: candidate = 4'd7;
                3: candidate = 4'd9;
                4: candidate = 4'd1;
                default: candidate = 4'd5;
            endcase
            delegated = mideleg[candidate];
            if (delegated)
                eligible = priv < 1 || (priv == 1 && mstatus[1]);
            else eligible = priv < 3 || (priv == 3 && mstatus[3]);
            if (!found && locally_pending[candidate] && eligible) begin
                found = 1'b1;
                selected = candidate;
            end
        end
        if (rst_n) begin
            if (sync_valid) begin
                enter = 1'b1;
                epc = sync_pc;
                cause = sync_cause;
                tval = sync_tval;
                if (priv != 3 && sync_cause < 64 &&
                    medeleg[sync_cause[5:0]]) target_priv = 2'd1;
                else target_priv = 2'd3;
            end else if (boundary_valid && found) begin
                enter = 1'b1;
                interrupt = 1'b1;
                epc = boundary_pc;
                cause = (64'd1 << 63) | {60'b0,selected};
                if (mideleg[selected]) target_priv = 2'd1;
                else target_priv = 2'd3;
            end
            if (enter) begin
                selected_vector = target_priv == 1 ? stvec : mtvec;
                vector = {selected_vector[63:2],2'b0};
                if (interrupt && selected_vector[1:0] == 1)
                    vector = vector + {58'b0,selected,2'b0};
            end
        end
    end
endmodule
