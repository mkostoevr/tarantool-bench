print output_file

set title main_title
set grid
set terminal png size 1024,768
set output sprintf('%s', output_file)
set xrange [xbegin:xend]
set key left top

plot input_file pointtype 7 pointsize 1 title brief
