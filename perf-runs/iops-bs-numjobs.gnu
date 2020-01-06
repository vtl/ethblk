filename = sprintf("gnuplot-%d-%d.dat", bs, numjobs)
bstitle = sprintf("Disk performance, randread, bs=%d. numjobs=%d", bs, numjobs)
pngfilename = sprintf("iops-bs%d-numjobs%d.png", bs, numjobs)

set terminal pngcairo dashed enhanced font "arial,10" fontscale 1.0 size 800,1000
#set term pngcairo dashed size 800,1000
set output pngfilename

set multiplot layout 3,1 title bstitle
set tmargin 3

set title "IOPS"
set style line 1 lt 2 lw 2 lc rgb 'black'
set key left box linestyle 1
set xlabel "Queue depth"
set ylabel "IOPS, k"
set grid
set logscale x 2

plot filename using 2:3 title "ethblk" with linespoints lc rgb 'red' lt 1 lw 2 ps 1.5 pt 13, \
     filename using 2:6 title "nvmet" with linespoints lc rgb 'green' lt 1 lw 2 ps 1.5 pt 7

set title "Bandwidth"
set xlabel "Queue depth"
set ylabel "Bandwidth, Gb/s"

plot filename using 2:4 title "ethblk" with linespoints lc rgb 'red' lt 1 lw 2 ps 1.5 pt 13, \
     filename using 2:7 title "nvmet" with linespoints lc rgb 'green' lt 1 lw 2 ps 1.5 pt 7

set title "CPU utilization per IO"
set key right box linestyle 1
set xlabel "Queue depth"
set ylabel "CPU ticks, million"

plot filename using 2:5 title "ethblk" with linespoints lc rgb 'red' lt 1 lw 2 ps 1.5 pt 13, \
     filename using 2:8 title "nvmet" with linespoints lc rgb 'green' lt 1 lw 2 ps 1.5 pt 7

unset multiplot
