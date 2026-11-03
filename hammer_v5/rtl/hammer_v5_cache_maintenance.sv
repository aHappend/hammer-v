module hammer_v5_cache_maintenance (
    input wire clk, rst_n,
    input wire req_valid,
    output wire req_ready,
    input wire [1:0] req_cmd,
    input wire [63:0] req_addr, req_wdata,
    input wire [7:0] req_wstrb,
    output wire rsp_valid, rsp_error,
    input wire rsp_ready,
    output wire [63:0] rsp_rdata,
    output wire cache_valid,
    input wire cache_ready,
    output wire [1:0] cache_cmd,
    output wire [63:0] cache_addr, cache_wdata,
    output wire [7:0] cache_wstrb,
    input wire cache_rsp_valid, cache_error,
    output wire cache_rsp_ready,
    input wire [63:0] cache_rdata,
    output wire maintenance_valid,
    input wire maintenance_ready,
    output wire [1:0] maintenance_cmd,
    input wire maintenance_rsp_valid, maintenance_error,
    output wire maintenance_rsp_ready
);
    localparam [2:0] IDLE=0, CACHE_WAIT=1, L2_REQUEST=2,
        L2_WAIT=3, RESPONSE=4;
    reg [2:0] state;
    reg [1:0] cmd_q;
    reg error_q;
    wire normal_response = state == CACHE_WAIT && !cmd_q[1];
    assign cache_valid = rst_n && state == IDLE && req_valid;
    assign req_ready = rst_n && state == IDLE && cache_ready;
    assign cache_cmd = cache_valid ? req_cmd : 2'b0;
    assign cache_addr = cache_valid ? req_addr : 64'b0;
    assign cache_wdata = cache_valid ? req_wdata : 64'b0;
    assign cache_wstrb = cache_valid ? req_wstrb : 8'b0;
    assign cache_rsp_ready = rst_n && state == CACHE_WAIT &&
        (cmd_q[1] || rsp_ready);
    assign rsp_valid = rst_n &&
        ((normal_response && cache_rsp_valid) || state == RESPONSE);
    assign rsp_error = rsp_valid &&
        (normal_response ? cache_error : error_q);
    assign rsp_rdata = rsp_valid && normal_response && !cache_error ?
        cache_rdata : 64'b0;
    assign maintenance_valid = rst_n && state == L2_REQUEST;
    assign maintenance_cmd = maintenance_valid ? cmd_q : 2'b0;
    assign maintenance_rsp_ready = rst_n && state == L2_WAIT;
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            cmd_q <= 0;
            error_q <= 0;
        end else begin
            case (state)
                IDLE: if (req_valid && req_ready) begin
                    cmd_q <= req_cmd;
                    error_q <= 0;
                    state <= CACHE_WAIT;
                end
                CACHE_WAIT: if (cache_rsp_valid && cache_rsp_ready) begin
                    if (!cmd_q[1]) state <= IDLE;
                    else begin
                        error_q <= cache_error;
                        if (cache_error) state <= RESPONSE;
                        else state <= L2_REQUEST;
                    end
                end
                L2_REQUEST: if (maintenance_ready) state <= L2_WAIT;
                L2_WAIT: if (maintenance_rsp_valid) begin
                    error_q <= maintenance_error;
                    state <= RESPONSE;
                end
                RESPONSE: if (rsp_ready) state <= IDLE;
                default: state <= IDLE;
            endcase
        end
    end
endmodule
