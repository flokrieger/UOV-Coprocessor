# Vitis HLS Synthesis
# Generates RTL from C++ for the ChipWhisperer cw308 Artix-7 100T board
# 
# Execute via: vitis_hls -f run_vitis_hls.tcl

set project "vitis_hls_uov"
set function "uov"
set ip_zip "./$project/vitis_hls_export.zip"
set rtl_dir "../rtl/vitis_hls_export"
set src_dir "../hls"
set part "xc7a100t-ftg256-2"

# Create project
open_project -reset=true $project
set_top $function
open_solution $project
set_part $part
create_clock -period 10

# Include sources
set design_files {}
set tb_files {}
foreach file [lsort [glob -nocomplain $src_dir/*.c $src_dir/*.cpp]] {
    set name [file tail $file]
    if {[string match {*_tb.*} $name] || [string match {tb.*} $name]} {
        lappend tb_files $file
    } else {
        lappend design_files $file
    }
}

foreach file $design_files {
    add_files $file -cflags "-I$src_dir"
}
foreach file $tb_files {
    add_files -tb $file -cflags "-I$src_dir"
}

# Run C Simulation
if {[catch {csim_design} err]} {
    puts ""
    puts "########################################################################"
    puts "##"
    puts "##  C SIMULATION FAILED - the testbench returned a non-zero value."
    puts "##"
    puts "##  $err"
    puts "##"
    puts "########################################################################"
    puts ""
    exit 1
}
puts "C simulation passed - continuing with C synthesis."

# Run C Synthesis
if {[catch {csynth_design} err]} {
    puts ""
    puts "########################################################################"
    puts "##"
    puts "##  C SYNTHESIS FAILED"
    puts "##"
    puts "##  $err"
    puts "##"
    puts "########################################################################"
    puts ""
    exit 1
}
puts "C synthesis passed - continuing with post-synthesis simulation."

# Run Post-Synthesis (RTL/C) Co-Simulation
if {[catch {cosim_design -rtl verilog} err]} {
    puts ""
    puts "########################################################################"
    puts "##"
    puts "##  POST-SYNTHESIS SIMULATION FAILED"
    puts "##"
    puts "##  $err"
    puts "##"
    puts "########################################################################"
    puts ""
    exit 1
}
puts "Post-synthesis simulation passed - continuing with IP export."

# Run IP Export
if {[catch {export_design -format ip_catalog -output $ip_zip} err]} {
    puts ""
    puts "########################################################################"
    puts "##"
    puts "##  IP EXPORT FAILED"
    puts "##"
    puts "##  $err"
    puts "##"
    puts "########################################################################"
    puts ""
    exit 1
}
puts "IP export passed - extracting RTL sources."

# Unpack the exported archive and copy its verilog/ subfolder into $rtl_dir.
set unpack_dir "./$project/rtl_unpack"
file delete -force $unpack_dir
file mkdir $unpack_dir

if {[catch {exec unzip -o -q $ip_zip -d $unpack_dir} err]} {
    puts ""
    puts "########################################################################"
    puts "##"
    puts "##  UNPACKING THE EXPORTED IP ARCHIVE FAILED"
    puts "##"
    puts "##  $err"
    puts "##"
    puts "########################################################################"
    puts ""
    exit 1
}

# An ip_catalog export keeps the sources under hdl/, older/other layouts put
# verilog/ directly at the archive root - accept either.
set verilog_dir [file join $unpack_dir hdl verilog]
file mkdir $rtl_dir
foreach f [glob -nocomplain -directory $rtl_dir -- *.v *.dat] {
    file delete -force $f
}

set copied 0
foreach f [glob -nocomplain -directory $verilog_dir -- *] {
    file copy -force -- $f [file join $rtl_dir [file tail $f]]
    incr copied
}

file delete -force $unpack_dir

puts "Copied $copied entries from $verilog_dir to $rtl_dir"

exit
