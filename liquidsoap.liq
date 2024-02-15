aac_midfi = %ffmpeg(format="mpegts",%audio(codec="aac",channels=2, ar=44100,b="192k"))

output.file.hls("www/stream", [("stream", aac_midfi)], mksafe(single("www/img/audio.ogg")))

server.telnet()

