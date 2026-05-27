import cv2
import os
import time
from datetime import datetime


recording = False
video_writer = None

RECORD_FOLDER="recordings"

os.makedirs(
RECORD_FOLDER,
exist_ok=True
)

# CAMERA INIT
camera = cv2.VideoCapture(0)

# fallback kapag ayaw default
if not camera.isOpened():

    camera = cv2.VideoCapture(
        0,
        cv2.CAP_MSMF
    )


SNAP_FOLDER = "snapshots"

if not os.path.exists(SNAP_FOLDER):
    os.makedirs(SNAP_FOLDER)


def start_recording():

    global recording
    global video_writer

    filename = os.path.join(

        RECORD_FOLDER,

        time.strftime(

            "record_%Y%m%d_%H%M%S.avi"

        )

    )

    fourcc = cv2.VideoWriter_fourcc(*'XVID')

    video_writer = cv2.VideoWriter(
        filename,
        fourcc,
        20,
        (640, 480)
    )

    recording = True


def stop_recording():

    global recording
    global video_writer

    recording = False

    if video_writer:

        video_writer.release()
        video_writer = None


def generate_frames():

    global recording

    while True:

        if not camera.isOpened():
            continue

        success, frame = camera.read()

        if not success:
            continue

        if recording and video_writer:

            video_writer.write(
                frame
            )

        ret, buffer = cv2.imencode(
            ".jpg",
            frame
        )

        if not ret:
            continue

        frame_bytes = buffer.tobytes()

        yield (

            b'--frame\r\n'
            b'Content-Type:image/jpeg\r\n\r\n'
            + frame_bytes +
            b'\r\n'

        )


def save_snapshot():

    success, frame = camera.read()

    if not success:
        return None

    filename = datetime.now().strftime(
        "%Y%m%d_%H%M%S.jpg"
    )

    path = os.path.join(
        SNAP_FOLDER,
        filename
    )

    cv2.imwrite(
        path,
        frame
    )

    return filename