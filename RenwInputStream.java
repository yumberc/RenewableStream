import java.io.*;

public class RenwInputStream extends InputStream {

  private InputStream in;
  private byte[] buffer = new byte[127];
  private int pos = 0, length = 0;
  private boolean more = true;

  public RenwInputStream(InputStream in) {
    this.in = in;
  }

  @Override
  public int read() throws IOException {
    if (pos < 0 || (pos >= length && end())) return -1;
    return buffer[pos++] & 0xFF;
  }

  @Override
  public int read(byte bt[], int off, int len) throws IOException {
    if ((off | len | (off + len) | (bt.length - (off + len))) < 0) throw new IndexOutOfBoundsException();
    if (pos < 0) return -1;
    if (len == 0) return 0;
    if (pos >= length && end()) return -1;
    int i = 0;
    for (int count, li; i < len ;) {
      if (pos >= length && end()) break;
      count = length - pos;
      li = len - i;
      if (count > li) count = li;
      System.arraycopy(buffer, pos, bt, off + i, count);
      pos += count;
      i += count;
    }
    return i;
  }

  private boolean end() throws IOException {
    pos = length = 0;
    if (more) {
      int c = in.read();
      if (c == -1) throw new IOException("EOS");
      more = (c & 0x80) != 0;  //0x80 = 1000 0000
      int ln = c & 0x7F;       //0x7F = 0111 1111
      if (ln > 0) {
        int l;
        while ((l = in.read(buffer, length, ln - length)) != -1) {
          length += l;
          if (length >= ln) break;
          //try { Thread.sleep(10); } catch (Exception e) { Thread.currentThread().interrupt(); }
        }
      }
    }
    if (length == 0) {
      more = true;
      pos = -1;
      return true;
    }
    return false;
  }

  public void renew() {
    pos = 0;
  }
}
