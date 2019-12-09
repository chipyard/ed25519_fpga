module ed25519_sign_core_tb;

    always begin
        #1 clk = ~clk;
    end
    
    //tb_core uut2();

    integer i = 0;

    // Inputs
    reg clk;
    reg rst;
    reg core_ena;
    reg [511:0] hashd_key;
    reg [511:0] hashd_ram;
    reg [511:0] hashd_sm;

    // Outputs
    wire core_ready;
    wire core_comp_done;
    wire [255:0] core_S;

    // Instantiate the Unit Under Test (UUT)
    ed25519_sign_S_core uut (
        .clk(clk),
        .rst(rst),
        .core_ena(core_ena),
        .core_ready(core_ready),
        .core_comp_done(core_comp_done),
        .hashd_key(hashd_key),
        .hashd_ram(hashd_ram),
        .hashd_sm(hashd_sm),
        .core_S(core_S)
    );

    reg [511:0] key_mem [0:100];
    reg [511:0] ram_mem [0:100];
    reg [511:0] sm_mem [0:100];
    reg [255:0] s_mem [0:100];

    initial begin
        // Initialize Inputs
        clk = 0;
        rst = 1;
        core_ena = 0;
        hashd_key = 0;
        hashd_ram = 0;
        hashd_sm = 0;

        // Read test vectors into memories
        $readmemh("./src/model/keyfile.dat", key_mem);
        $readmemh("./src/model/ramfile.dat", ram_mem);
        $readmemh("./src/model/smfile.dat", sm_mem);
        $readmemh("./src/model/sfile.dat", s_mem);

        // Wait 100 ns for global reset to finish
        #100;
        rst = 0;
    end

    /* Give input and enable core */
    always @* begin
        hashd_key = uut.changeEndian_512(key_mem[i]);
        hashd_ram = ram_mem[i];
        hashd_sm = sm_mem[i];
        core_ena = 1'b0;
        if (core_ready) begin
            core_ena = 1'b1;
        end
    end

    /* Verification of result */
    always @* begin
        if (core_comp_done) begin
            #2;
            $display("S: %064x", core_S);
            if (core_S != s_mem[i]) begin
                $display("ERROR");
                $display("key: %x", key_mem[i]);
                $display("pk: %x", ram_mem[i]);
                $display("m: %x", sm_mem[i]);
                $display("S: %x", s_mem[i]);
                $display(" : %x", core_S);
                $stop;
            end
            else begin
                $display("%d passed", i);
                i = i + 1;
            end
        end
    end

endmodule

