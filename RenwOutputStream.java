import java.io.*;

public class RenwOutputStream extends OutputStream {

  private OutputStream out;
  private byte buffer[];
  private int pos = 0;

  public RenwOutputStream(OutputStream out, int size) {
    if (size < 1 || size > 127) throw new IllegalArgumentException("buffer size is " + size + ", should be 1-127");
    this.out = out;
    this.buffer = new byte[size];
  }

  public RenwOutputStream(OutputStream out) {
    this(out, 127);
  }

  @Override
  public void write(int b) throws IOException {
    if (pos >= buffer.length) flushBuffer(true);
    buffer[pos++] = (byte)b;
  }

  @Override
  public void write(byte bt[], int off, int len) throws IOException {
    if ((off | len | (off + len) | (bt.length - (off + len))) < 0) throw new IndexOutOfBoundsException();
    for (int count, li, i = 0; i < len;) {
      if (pos >= buffer.length) flushBuffer(true);
      count = buffer.length - pos;
      li = len - i;
      if (count > li) count = li;
      System.arraycopy(bt, off + i, buffer, pos, count);
      pos += count;
      i += count;
    }
  }

  private void flushBuffer(boolean more) throws IOException {
    out.write(more ? pos | 0x80 : pos);  //0x80 = 1000 0000
    if (pos > 0) out.write(buffer, 0, pos);
    pos = 0;
  }

  @Override
  public void close() throws IOException {
    flushBuffer(false);
    out.flush();
  }
}
