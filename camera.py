import cv2
import os
import time
from datetime import datetime

recording = False
video_writer = None

RECORD_FOLDER = "recordings"

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


def add_cctv_overlay(frame):

    timestamp = datetime.now().strftime(
        "NETSENTINEL CAM-01 | %Y-%m-%d %H:%M:%S"
    )

    cv2.rectangle(
        frame,
        (5, 5),
        (320, 45),
        (0, 0, 0),
        -1
    )

    # CCTV timestamp text
    cv2.putText(
        frame,
        timestamp,
        (15, 32),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.8,
        (0, 255, 0),
        2,
        cv2.LINE_AA
    )

    return frame


def generate_frames():

    global recording
    global video_writer

    while True:

        if not camera.isOpened():
            time.sleep(0.5)
            continue

        success, frame = camera.read()

        if not success:
            time.sleep(0.01)
            continue

        # ADD TIMESTAMP OVERLAY
        frame = add_cctv_overlay(frame)

        # RECORDING
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
            b'Content-Type: image/jpeg\r\n\r\n'
            + frame_bytes +
            b'\r\n'

        )