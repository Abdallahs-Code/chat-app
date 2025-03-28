PGDMP      '                }            chatdb    17.2    17.2 #    @           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                           false            A           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                           false            B           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                           false            C           1262    18815    chatdb    DATABASE     �   CREATE DATABASE chatdb WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'English_United States.1252';
    DROP DATABASE chatdb;
                     postgres    false            �            1259    18946    friend_requests    TABLE     �   CREATE TABLE public.friend_requests (
    id integer NOT NULL,
    sender_id integer NOT NULL,
    receiver_id integer NOT NULL,
    "timestamp" timestamp without time zone
);
 #   DROP TABLE public.friend_requests;
       public         heap r       postgres    false            �            1259    18945    friend_requests_id_seq    SEQUENCE     �   CREATE SEQUENCE public.friend_requests_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 -   DROP SEQUENCE public.friend_requests_id_seq;
       public               postgres    false    218            D           0    0    friend_requests_id_seq    SEQUENCE OWNED BY     Q   ALTER SEQUENCE public.friend_requests_id_seq OWNED BY public.friend_requests.id;
          public               postgres    false    217            �            1259    18963    friends    TABLE     �   CREATE TABLE public.friends (
    id integer NOT NULL,
    user1_id integer NOT NULL,
    user2_id integer NOT NULL,
    "timestamp" timestamp without time zone
);
    DROP TABLE public.friends;
       public         heap r       postgres    false            �            1259    18962    friends_id_seq    SEQUENCE     �   CREATE SEQUENCE public.friends_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.friends_id_seq;
       public               postgres    false    220            E           0    0    friends_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.friends_id_seq OWNED BY public.friends.id;
          public               postgres    false    219            �            1259    19030    messages    TABLE     �   CREATE TABLE public.messages (
    id integer NOT NULL,
    sender_id integer NOT NULL,
    receiver_id integer NOT NULL,
    content bytea NOT NULL,
    "timestamp" timestamp without time zone
);
    DROP TABLE public.messages;
       public         heap r       postgres    false            �            1259    19029    messages_id_seq    SEQUENCE     �   CREATE SEQUENCE public.messages_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.messages_id_seq;
       public               postgres    false    224            F           0    0    messages_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.messages_id_seq OWNED BY public.messages.id;
          public               postgres    false    223            �            1259    18981    users    TABLE     �   CREATE TABLE public.users (
    id integer NOT NULL,
    username character varying(80) NOT NULL,
    password text NOT NULL,
    "timestamp" timestamp without time zone
);
    DROP TABLE public.users;
       public         heap r       postgres    false            �            1259    18980    users_id_seq    SEQUENCE     �   CREATE SEQUENCE public.users_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.users_id_seq;
       public               postgres    false    222            G           0    0    users_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.users_id_seq OWNED BY public.users.id;
          public               postgres    false    221            �           2604    18949    friend_requests id    DEFAULT     x   ALTER TABLE ONLY public.friend_requests ALTER COLUMN id SET DEFAULT nextval('public.friend_requests_id_seq'::regclass);
 A   ALTER TABLE public.friend_requests ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    217    218    218            �           2604    18966 
   friends id    DEFAULT     h   ALTER TABLE ONLY public.friends ALTER COLUMN id SET DEFAULT nextval('public.friends_id_seq'::regclass);
 9   ALTER TABLE public.friends ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    219    220    220            �           2604    19033    messages id    DEFAULT     j   ALTER TABLE ONLY public.messages ALTER COLUMN id SET DEFAULT nextval('public.messages_id_seq'::regclass);
 :   ALTER TABLE public.messages ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    223    224    224            �           2604    18984    users id    DEFAULT     d   ALTER TABLE ONLY public.users ALTER COLUMN id SET DEFAULT nextval('public.users_id_seq'::regclass);
 7   ALTER TABLE public.users ALTER COLUMN id DROP DEFAULT;
       public               postgres    false    222    221    222            7          0    18946    friend_requests 
   TABLE DATA           R   COPY public.friend_requests (id, sender_id, receiver_id, "timestamp") FROM stdin;
    public               postgres    false    218   �&       9          0    18963    friends 
   TABLE DATA           F   COPY public.friends (id, user1_id, user2_id, "timestamp") FROM stdin;
    public               postgres    false    220   �&       =          0    19030    messages 
   TABLE DATA           T   COPY public.messages (id, sender_id, receiver_id, content, "timestamp") FROM stdin;
    public               postgres    false    224   >'       ;          0    18981    users 
   TABLE DATA           D   COPY public.users (id, username, password, "timestamp") FROM stdin;
    public               postgres    false    222   ;       H           0    0    friend_requests_id_seq    SEQUENCE SET     D   SELECT pg_catalog.setval('public.friend_requests_id_seq', 8, true);
          public               postgres    false    217            I           0    0    friends_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.friends_id_seq', 4, true);
          public               postgres    false    219            J           0    0    messages_id_seq    SEQUENCE SET     >   SELECT pg_catalog.setval('public.messages_id_seq', 47, true);
          public               postgres    false    223            K           0    0    users_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.users_id_seq', 20, true);
          public               postgres    false    221            �           2606    18951 $   friend_requests friend_requests_pkey 
   CONSTRAINT     b   ALTER TABLE ONLY public.friend_requests
    ADD CONSTRAINT friend_requests_pkey PRIMARY KEY (id);
 N   ALTER TABLE ONLY public.friend_requests DROP CONSTRAINT friend_requests_pkey;
       public                 postgres    false    218            �           2606    18968    friends friends_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.friends
    ADD CONSTRAINT friends_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.friends DROP CONSTRAINT friends_pkey;
       public                 postgres    false    220            �           2606    19037    messages messages_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_pkey;
       public                 postgres    false    224            �           2606    18988    users users_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.users DROP CONSTRAINT users_pkey;
       public                 postgres    false    222            �           2606    18990    users users_username_key 
   CONSTRAINT     W   ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);
 B   ALTER TABLE ONLY public.users DROP CONSTRAINT users_username_key;
       public                 postgres    false    222            �           2606    19043 "   messages messages_receiver_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_receiver_id_fkey FOREIGN KEY (receiver_id) REFERENCES public.users(id);
 L   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_receiver_id_fkey;
       public               postgres    false    224    4766    222            �           2606    19038     messages messages_sender_id_fkey    FK CONSTRAINT     �   ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_sender_id_fkey FOREIGN KEY (sender_id) REFERENCES public.users(id);
 J   ALTER TABLE ONLY public.messages DROP CONSTRAINT messages_sender_id_fkey;
       public               postgres    false    222    4766    224            7   /   x�3�4��4�4202�50�52V02�26�2��375125����� �@�      9   Z   x�]���0D�s��d`B����xs<�7߇��C��8�6��&��;���ҵH��]|��:.劘%1|��C`M6J-�˭"� ڇ�      =      x���K���E��*�� ��\�& I�����AO��r[Rw	d�^�x���W���������r�ZS�ծ6Zoרc�RZ���Q��~�g?�c�����V[n?|�g[-�2f�m����~�^fo��GO�詾�hWo#���|��[�z�9��Kn��R�Uژů��ܳ?�G��l;�x��_y������R��y�����m˚Z~06�Ug?�(��c�U��z���x	�c��й������k`f�V�SZ�ȝ>�ઉ?���,��aV����t��b4��x��Gc��kᄭg\~���ؖ�������|���ܻZ�7��$�{�1ΐq9?G%���mWm���>��k�c�X�y�^g��wT>C�q
>��*X\_E�W��x�খj#�'Ny���~f���j$Q���V��TRq�7�>����ol&X��~�Ĭ��y/�6	G��|�)w�D����8Ȇ�M���A	���D(�|&�5��ν����������r_TS1I�s`�Y��kꬓ��ǣ?q��O]I�a�Od�cX�k��H�yo�F8H��}��`P�$UjG�N�a�L��0�3*��+i%�e���o5����2�d-�X�	��HX�����6�s��=	?ӣ�4?�g�D]?Z�9ß�F僵���{�}f2a�_���'��I3�n�X��c�_^���/b�8��{ ���"�~XF�Z|gTҕ��d (���B��x��'q�8�] �Y�������+�cl>Y[ҽ�`̹�o�Ӝ��)-���O�X���5��)v6��a)Q%��������ǩ׈��@5����L`�a��M*�����d�hV��F�+�VLal��֎{�����8���Wk��,Q}���?���YLv�O���^��yHD�d)�����L�˧��N� ����W��ϭb�3���� �ߧ���z"�6c"���6�{N�Rv���o��-{ )��<[~��YAj8Z\X����D5Q���M�&�I��.��ض��j�1=w)<ǋ�ݷ`��$ڈ�(p����/Q$�����%zխ�{MkK�/�O�$&�����a��	��2=;�z� V ��lj�  F:�!�s  ��1�������q�} ��KLLq]Q�6d{��]`�>��M>����jn��x�aK�7s.�D&�|�h��SW�A`��;9�A�a�N�0����L������9�yO�<Z*Y�.�͋z�]G�!:��3�@ۋ����C�JC�X����W�e��b�F �A9�I8��r"��x�,�"b�6������6`����U,�,�r�]�0]��g�c���"�]�I�0QVr[�W�Uq��m/����5Ok&	w��U&9FIcYW�`A��-��"�y����Ҹ�rK_Y\�����wA\^r6�:-=��� 5D�f!���qU��,�Ԣ����7����*���y5+��]�R 2��"QЁ	��)�\��2�MkA�yۥ?sK�7s���b��&2%��WC�	� ����!:�t�N&)��$��ҟ�(��V�L]�<[6���0W��V����erA�a���1���SP��Q���P0�y�d� _��ܳ#2��S�UjDΒ
F*̆��e/����Ԣ����
$�D�1����l���
p�P�5 ?�t�'�G�T���m8-�mL�>�T����z�m�\7l�bn��P4�B�]�
�/�A���~��.��*�n�+ѕ.~�I#&FIp���q"�(�HY@������i�IdC̥�.*�:{���x\�e��kqN8?���i��9.�o�f�������!���pb����"��3�)js���f�
2�X���L20ڻ����u�M�t��+(��;h�&����"�_�D�%$���Om�mn�9�Ծ������9r�l�;C��0�N�pZ�K��&�-L�O5I��/��
���N\m��Z���?�*��'���f�k.��i�l�6�7(姣��z��n�Gމ�W��[@��)��>�su��I1�
�/bD��tǨ �$!�K2,�����vg�a:ͱk8���p%0����n]O���r��~�,!��ۿ>�a.$��m�_I���5� ��:��ve�̖mk6���'�_���gZ4��i�X;<0��)(�5:��D$&���V�y�����ۺ�K\wF����}#��Ѵg�k�ln�g�yJ۷���5�"�vXLS���&�>B�Zp	_T�W�m�j�)¨�$�&�/�21�$l��< ݛL��0��g��{	����m�p���׺�`�1�8��و07�w9��U�JҚ��9���g�E~P_�H�c	Jp�:Jz�GE���^B�b�JWĨJ:��wH�p����=�͍|Pd3���ϥ�1�>βE��Er�@K�͆�4��Ed����WV"PA$l$�.��¡2� g7�(I�U�$i8}�$⨣Hc�ո)�@H= 7��y���e/e��U�p��F�$HUr�i�(�C�%(��k�-eU�69��;�H�C��@'=&N�x�VKc�P�Rݪ�M� r�qN&��f������J ���h(�9f�,�iRDɃ��X�E(dl�+�j�Y��vN�a'&Lg���NYR��#�����k�����ꪂ3=|}������!�F�HӦ(�Ŝ���Sp,�.�]��R/�h�ب�����힕� z����{�GLp�{����&&^T���ј�b,Q�*Y=t�`�94��V��+�:<Ǐ�Sy'Ъ2��*:ߪy�b�L��D'|N�v/���	���U=����$�� tq8J��כ�7x�|�P��2���T���(��3�ϋ?�l�;(&̥��Ώh_�#�������w,�Y�saU�����
E��dX�����^�|T�$4Y�Z`��ە�Z�B�2���%�t�I$e�*|2��4��AH�B��K�������z{�P���Ʊ�̖aU<�M"7��
u�n��u�-�d�b����r���x���P�4�a��=uG��wҿ��׈�(_�J�
�K�5)b2��ԅ�BO�
siD+&έ|gU��������9=R�'�i�?������"��²#	P�s�W���ߐ��Î�/G�&�u�}H�qu(�яg(RJ,6eS���B[ᢦF����u�J_d���wVţ�K����AD���H���Ǯ�,0�]�%���+{Rl=����#�&�4��P_l9��T/5�Xm���؎ ;�h#�ݜoqT~��F/(u+�IUk���_��,;���)]i��K�۫L���βu�ho�3Jo���^.�<�J)s�Ѩ��K_���)�S�jy�Ǘ-[� fQ�]�������[�&k+�IƸer#&��9���F	�'97�
��\�Lz��8���y��Ւ���.���"�K�C�׍�Rf�|/w�i6)�!��m%�Q���fs��1��_�����
v�,N׉)J�J]���r�BR�2�/J)�]Z��x�N9�f��.���:�;A�i&�C�R�qE?�� ���S=�C]�֮S��W�ݒ�-ݒ��d�N�$���8
&�gT��i>�
�m!F��H "�Y��-�e{�����R=0��&��Z��ÿ�n#_.�}�1����ؑ�Fv�YD����m��s2�ӽ��o�;��{�����s	�8�2�A�k�\-���_h���$1�(r8z� ��U��t_�/<�p�kj�N��#0�L/���5fKy�\��PM:s�G�QF��k�m+�I�~�����dunN�W�L|�����0��W��@����	��v+�vkDw29H��C��$�������X�O�
�#������q�K�s�Έ�+���I@��L�v:��X�z�B�3�a����Kc��,�������%���%��(�D(T)r�l�9L�[�W�\B�@�]�P��SDH�'�2�>�!U��~+ �  iO"3�j��>�4����h$r"�T������ܳ,T���P� ���pƴ*y��������2bː�[S�N8~�?^��p�bE�7H��&����~���厲��I��^�wO��׭���������J6D����J%^9����H�U'q�$�#��ו ��e�b��u� ��)��wJH���߻E�P�E���Kd+����ޅ�(vt'�O���To�=���K|���ӊ��B�_I����J���{H�O���T��d�*d�� �f��i�QƥF�qI�dݧu���K�i;c�!��6y���^��*uI[Ϳ������u[��O��@��K85d(k�|ڻ���zsfp��6�o7.%"���x)NAS�dn��z���pn��Ҽ#h�08(q���T(�;�������|����5�Z�ګ~ē�Vs�Ӭ��H^�PrWGvk�8q|�\���c�"��g�8.�/�W]j�{g`��F�̏��;�ڈ�����E���Gl�[�%}F�M��Ox�E�"�[N���������ӊ!�]m
�`n��殍�.^rʪ�U߻���&�hP�n12xo��C�
RJ�+W���d/7AQ�aѢ�uw�^��h�=/Ό��kC��G�`�����^L�J����b�hw�r��r�I����D���S(αC}����U�'��m�3*%y�,F��������.��yI���q7n�{���+��#���Љ�	n����[Y*�[�_�Y�'g���z�>��ʙsa ���#D�7��kl=�V�T��{�I����mHq��t�]����p��n`��n��)nx�8�#_���\�Z���}_^��O�*�U��ܸG@{'�Ѝ�JEVc H�*/��^5� ΊBs�%��@��u�~aR�}���9h������bd��u�p�;���}��*��J������1���N7o���۶m��x�$      ;   �  x�e��R�G��3O��lM�֒zv.l��bL���F}qapl�e�>b�8l�n�?��Q�&ڈ���|�_���3�������������%��]�3����F�	Pb����B,��lګ�$w,(��,Cg/F���	f�u���gqT��;�X����n��7e�Py	����=���Qu+���4�s���C;�sś�ߪ���j1�S�ʔ!�b�.��:�+n^���J��}3� �ZL��(��V�����R�6��-�0�c���f��u�@a{Խ�Aa,�lQ7�=�>��~������ӳu������]L���lP�0�G��jbV.�Qt�vQo��u�#�,�E�z����X>M���U�8�	��r��M��/=Q���2nџR5��\}���,�������w���h'���6�A&�0��Պ��M4�f�Zs���&�&PA�iɲtoAz���0�Xn;p�Vg4uf�dҸVh����_��=���3�b���]<������ۻÿ��r�/�I�\3�-�Ь���WvrCPn�O�h/:k-2�P2sk����X�1Yӵ�0j��C_޻�A��R:��9x���{�E�=�39і`3�o�c�y/�������O.���J����d����:4R�c:�3W+ԙU�r�;Ƙ#R$�˨ق����擐�����ہ5�^�J����z>+�<���0p��� ����`�����<�     