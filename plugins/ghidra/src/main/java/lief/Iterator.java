package lief;

public abstract class Iterator<E> extends lief.Base implements java.util.Iterator<E> {
    protected Iterator(long impl) {
        super(impl);
    }
}
