import java.util.Vector;

public class Queue {
    private Vector vec = new Vector();

    public void enqueue(Object o) {
        vec.addElement(o);      // add to end
    }

    public Object dequeue() {
        if (vec.size() == 0) return null;
        Object o = vec.elementAt(0);
        vec.removeElementAt(0); // remove from front
        return o;
    }

    public boolean isEmpty() {
        return vec.size() == 0;
    }

    public int size() {
        return vec.size();
    }
}