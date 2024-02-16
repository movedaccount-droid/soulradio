aac_midfi = %ffmpeg(format="mpegts",%audio(codec="aac",channels=2, ar=44100,b="192k"))

def request_function() =
	result = list.hd(default="", process.read.lines("cat testmessage.txt | nc localhost 8081"))
	request.create(result)
end

main = request.dynamic(request_function)
output.file.hls("www/stream", [("stream", aac_midfi)], mksafe(main))

server.telnet()
