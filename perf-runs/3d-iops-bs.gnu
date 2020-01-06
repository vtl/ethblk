filename = sprintf("gnuplot-%d.dat", bs)
bstitle = sprintf("Disk performance, randread, bs=%d", bs)
pngfilename = sprintf("3d-iops-bs%d.png", bs)

set terminal pngcairo enhanced font "arial,10" fontscale 1.0 size 1024,768
set output pngfilename
set boxwidth 0.5#0.4 absolute
set boxdepth 0.8# 0.3
set style fill solid 0.50 border

set grid nopolar
set grid xtics nomxtics ytics nomytics ztics nomztics nortics nomrtics \
 nox2tics nomx2tics noy2tics nomy2tics nocbtics nomcbtics
set grid vertical layerdefault   lt 0 linecolor 0 linewidth 1.000,  lt 0 linecolor 0 linewidth 1.000
#unset key
set wall z0  fc  rgb "slategrey"  fillstyle  transparent solid 0.50 border lt -1
#set view 59, 24, 1, 1

set view 83, 6, 1.1, 1.1

#set style data lines

set xyplane at 0
set title sprintf("IOPS, bs=%d", bs)

set xrange [ 320 : 0.8 ] noreverse writeback
set logscale x 2
set xtics offset 0,-2
set xlabel "Queue depth" offset 0,-1

set yrange [ 0.7 : 34 ] noreverse nowriteback
set logscale y 2
set ylabel "Workers"
set ytics offset 1

#set zrange [ 0 : 4000 ] noreverse writeback

set zlabel "IOPS, k" rotate by 90 offset -1

#set cbrange [ * : * ] noreverse writeback
#set rrange [ * : * ] noreverse writeback
set pm3d depthorder base
set pm3d interpolate 1,1 flush begin noftriangles border linewidth 1.000 dashtype solid corners2color mean
#set pm3d lighting primary 0.5 specular 0.2 spec2 0

NO_ANIMATION = 1

splot filename using 2:1:3 with boxes title "ethblk" lc rgb 'green', \
      filename using 2:1:6 with boxes title "nvmet" lc rgb 'yellow'
