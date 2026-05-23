import cv2
import os
from datetime import datetime


recording=False

video_writer=None

def start_recording():

    global recording
    global video_writer

    filename=time.strftime(

    "record_%Y%m%d_%H%M%S.mp4"

    )

    fourcc=cv2.VideoWriter_fourcc(
    *'mp4v'
    )

    video_writer=cv2.VideoWriter(

    filename,

    fourcc,

    20,

    (640,480)

    )

    recording=True


def stop_recording():

    global recording
    global video_writer

    recording=False

    if video_writer:

        video_writer.release()

camera=cv2.VideoCapture(0)

SNAP_FOLDER="snapshots"

if not os.path.exists(SNAP_FOLDER):
    os.makedirs(SNAP_FOLDER)


def generate_frames():

    while True:

        success,frame=camera.read()

        if recording:
            video_writer.write(
                frame
            )

        if not success:
            break

        ret,buffer=cv2.imencode(".jpg",frame)

        frame_bytes=buffer.tobytes()

        yield(
            b'--frame\r\n'
            b'Content-Type:image/jpeg\r\n\r\n'
            +frame_bytes+
            b'\r\n'
        )


def save_snapshot():

    success,frame=camera.read()

    if success:

        filename=datetime.now().strftime(
            "%Y%m%d_%H%M%S.jpg"
        )

        path=os.path.join(
            SNAP_FOLDER,
            filename
        )

        cv2.imwrite(path,frame)

        return filename

    return None