module hammer_v3_page_leaf (
    input wire [63:0] va,
    input wire [43:0] ppn,
    input wire [1:0] level,
    input wire [7:0] flags,
    input wire [1:0] access_kind, priv,
    input wire sum, mxr,
    output reg [55:0] pa,
    output reg fault
);
    always @* begin
        pa = {ppn,va[11:0]};
        fault = !flags[0] || (!flags[1] && flags[2]) ||
            (!flags[1] && !flags[3]) || !flags[6] ||
            va[63:39] != {25{va[38]}};
        case (level)
            2'd0: begin end
            2'd1: begin
                pa = {ppn[43:9],va[20:0]};
                if (|ppn[8:0]) fault = 1'b1;
            end
            2'd2: begin
                pa = {ppn[43:18],va[29:0]};
                if (|ppn[17:0]) fault = 1'b1;
            end
            default: fault = 1'b1;
        endcase
        if (priv == 0 && !flags[4]) fault = 1'b1;
        if (priv == 1 && flags[4] && (access_kind == 0 || !sum))
            fault = 1'b1;
        case (access_kind)
            2'd0: if (!flags[3]) fault = 1'b1;
            2'd1: if (!flags[1] && !(mxr && flags[3])) fault = 1'b1;
            2'd2: if (!flags[2] || !flags[7]) fault = 1'b1;
            2'd3: if (!flags[1] || !flags[2] || !flags[7]) fault = 1'b1;
        endcase
    end
endmodule
