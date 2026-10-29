module hammer_v3_data_router #(
    parameter integer DMEM_WORDS = 8192
) (
    input wire clk, rst_n, req_valid,
    output wire req_ready,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    input wire [1:0] req_cmd, req_size,
    output wire rsp_valid,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire rsp_error,
    output wire [4:0] target_valid,
    input wire [4:0] target_ready,
    output wire [63:0] target_addr, target_wdata,
    output wire [7:0] target_wstrb,
    output wire [1:0] target_cmd, target_size,
    input wire [4:0] target_rsp_valid, target_rsp_error,
    output wire [4:0] target_rsp_ready,
    input wire [319:0] target_rdata
);
    localparam [1:0] IDLE=0, ISSUE=1, WAITING=2, RESPONSE=3;
    localparam [63:0] LIMIT = 64'h10000000 + DMEM_WORDS*64'd8;
    reg [1:0] state;
    reg [2:0] destination, decode;
    reg mapped, error_q;
    reg [63:0] addr_q, data_q, read_q;
    reg [7:0] mask_q, read_mask;
    reg [1:0] cmd_q, size_q;
    wire misaligned = (req_size == 1 && req_addr[0]) ||
        (req_size == 2 && |req_addr[1:0]) ||
        (req_size == 3 && |req_addr[2:0]);
    always @* begin
        mapped = 1'b1;
        decode = 0;
        if (req_cmd[1] ||
            (req_addr >= 64'h10000000 && req_addr < LIMIT) ||
            (req_addr >= 64'h80000000 && req_addr < 64'h100000000)) decode = 0;
        else if ((req_addr >= 64'h02000000 && req_addr < 64'h02000004) ||
                 (req_addr >= 64'h02004000 && req_addr < 64'h02004008) ||
                 (req_addr >= 64'h0200bff8 && req_addr < 64'h0200c000)) decode = 1;
        else if (req_addr >= 64'h0c000000 && req_addr < 64'h10000000) decode = 2;
        else if (req_addr >= 64'h10010000 && req_addr < 64'h10010100) decode = 3;
        else if (req_addr >= 64'h40000000 && req_addr < 64'h40010000) decode = 4;
        else mapped = 1'b0;
        case (req_size)
            0: read_mask = 8'h01 << req_addr[2:0];
            1: read_mask = 8'h03 << req_addr[2:0];
            2: read_mask = 8'h0f << req_addr[2:0];
            default: read_mask = 8'hff;
        endcase
    end
    assign req_ready = rst_n && state == IDLE;
    assign rsp_valid = rst_n && state == RESPONSE;
    assign rsp_error = rsp_valid && error_q;
    assign rsp_rdata = rsp_valid && !error_q ? read_q : 64'b0;
    assign target_valid = rst_n && state == ISSUE ? 5'b00001 << destination : 5'b0;
    assign target_addr = |target_valid ? addr_q : 64'b0;
    assign target_wdata = |target_valid ? data_q : 64'b0;
    assign target_wstrb = |target_valid ? mask_q : 8'b0;
    assign target_cmd = |target_valid ? cmd_q : 2'b0;
    assign target_size = |target_valid ? size_q : 2'b0;
    assign target_rsp_ready = rst_n && state == WAITING ?
        5'b00001 << destination : 5'b0;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            destination <= 0;
            addr_q <= 0;
            data_q <= 0;
            read_q <= 0;
            mask_q <= 0;
            cmd_q <= 0;
            size_q <= 0;
            error_q <= 0;
        end else begin
            case (state)
                IDLE: if (req_valid) begin
                    destination <= decode;
                    addr_q <= req_addr;
                    data_q <= req_wdata;
                    mask_q <= req_cmd == 0 ? read_mask : req_wstrb;
                    cmd_q <= req_cmd;
                    size_q <= req_size;
                    read_q <= 0;
                    error_q <= !mapped || (!req_cmd[1] && misaligned);
                    if (!mapped || (!req_cmd[1] && misaligned)) state <= RESPONSE;
                    else state <= ISSUE;
                end
                ISSUE: if (target_ready[destination]) state <= WAITING;
                WAITING: if (target_rsp_valid[destination]) begin
                    read_q <= target_rdata[destination*64 +: 64];
                    error_q <= target_rsp_error[destination];
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
