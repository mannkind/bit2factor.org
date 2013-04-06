#!/bin/ruby
def inline(type, file, outfile)
  outfile.puts `yui-compressor --type #{type} #{file}`
end

# Couldn't get node's inliner to work; writing something hacky...
if ARGV.size != 2
  puts "Usage: ruby compile.rb inputfile outputfile"
else
  inputfile = ARGV[0]
  outputfile = ARGV[1]
  puts "Input file: #{inputfile}"
  puts "Output file: #{outputfile}"
  
  File.open(outputfile, 'w') do |outfile|  
    File.open(inputfile).readlines.each do |line|
      m = line.strip.match /script src="(.*?)"/
      k = line.strip.match /link href="(.*?)"/
      if m != nil && m[1] != nil
        file = m[1]

        outfile.puts "<script type=\"text/javascript\" id=\"#{file}\">"
        inline 'js', file, outfile
        outfile.puts "</script>"
      elsif k != nil && k[1] != nil
        file = k[1]

        outfile.puts "<style type=\"text/css\" id=\"#{file}\">"
        inline 'css', file, outfile
        outfile.puts "</style>"
      else
        # put a normal line from the original file into the new one
        outfile.puts line
      end
    end
  end
end


