module hammer_v3_cache_arbiter (
    input wire clk, rst_n,
    input wire [2:0] req_valid,
    output wire [2:0] req_ready,
    input wire [5:0] req_cmd,
    input wire [191:0] req_addr, req_wdata,
    input wire [23:0] req_wstrb,
    output wire [2:0] rsp_valid, rsp_error,
    input wire [2:0] rsp_ready,
    output wire [191:0] rsp_rdata,
    output wire out_valid,
    input wire out_ready,
    output wire [1:0] out_cmd,
    output wire [63:0] out_addr, out_wdata,
    output wire [7:0] out_wstrb,
    input wire out_rsp_valid, out_rsp_error,
    output wire out_rsp_ready,
    input wire [63:0] out_rsp_rdata
);
    localparam [1:0] IDLE=0, ISSUE=1, WAITING=2, RESPONSE=3;
    reg [1:0] state, owner, next_owner;
    reg [1:0] cmd_q;
    reg [63:0] addr_q, data_q, read_q;
    reg [7:0] mask_q;
    reg error_q, found;
    reg [1:0] select;
    genvar n;
    always @* begin
        found = |req_valid;
        select = next_owner;
        case (next_owner)
            0: if (req_valid[0]) select = 0;
               else if (req_valid[1]) select = 1;
               else select = 2;
            1: if (req_valid[1]) select = 1;
               else if (req_valid[2]) select = 2;
               else select = 0;
            default: if (req_valid[2]) select = 2;
                     else if (req_valid[0]) select = 0;
                     else select = 1;
        endcase
    end
    assign req_ready = rst_n && state == IDLE && found ? 3'b001 << select : 3'b0;
    assign rsp_valid = rst_n && state == RESPONSE ? 3'b001 << owner : 3'b0;
    assign rsp_error = rsp_valid & {3{error_q}};
    generate
        for (n = 0; n < 3; n = n + 1) begin : g_response
            assign rsp_rdata[n*64 +: 64] = rsp_valid[n] && !error_q ? read_q : 64'b0;
        end
    endgenerate
    assign out_valid = rst_n && state == ISSUE;
    assign out_cmd = out_valid ? cmd_q : 2'b0;
    assign out_addr = out_valid ? addr_q : 64'b0;
    assign out_wdata = out_valid ? data_q : 64'b0;
    assign out_wstrb = out_valid ? mask_q : 8'b0;
    assign out_rsp_ready = rst_n && state == WAITING;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            owner <= 0;
            next_owner <= 0;
            cmd_q <= 0;
            addr_q <= 0;
            data_q <= 0;
            read_q <= 0;
            mask_q <= 0;
            error_q <= 0;
        end else begin
            case (state)
                IDLE: if (found) begin
                    owner <= select;
                    next_owner <= select == 2 ? 2'd0 : select + 2'd1;
                    cmd_q <= req_cmd[select*2 +: 2];
                    addr_q <= req_addr[select*64 +: 64];
                    data_q <= req_wdata[select*64 +: 64];
                    mask_q <= req_wstrb[select*8 +: 8];
                    state <= ISSUE;
                end
                ISSUE: if (out_ready) state <= WAITING;
                WAITING: if (out_rsp_valid) begin
                    read_q <= out_rsp_rdata;
                    error_q <= out_rsp_error;
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready[owner]) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
